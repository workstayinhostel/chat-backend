import 'dotenv/config';
import http from 'node:http';
import crypto from 'node:crypto';
import dns from 'node:dns';
import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import multer from 'multer';
import { rateLimit } from 'express-rate-limit';
import { WebSocketServer, WebSocket } from 'ws';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import { createClient } from '@supabase/supabase-js';
import { User, Group, Chat, Message, Media, Call } from './models.js';

const {
  JWT_SECRET,
  ENC_KEY,
  MONGO_URI,
  MONGO_DNS_SERVERS,
  GOOGLE_CLIENT_ID,
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  PORT = 4000,
  ORIGIN = 'http://192.168.1.83:8000,http://localhost:8000'
} = process.env;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('Set a random JWT_SECRET with at least 32 characters in server/.env');
}
if (!ENC_KEY || !/^[a-f0-9]{64}$/i.test(ENC_KEY)) {
  throw new Error('Set a random 64-character hexadecimal ENC_KEY in server/.env');
}
if (!GOOGLE_CLIENT_ID) {
  throw new Error('Set GOOGLE_CLIENT_ID to your Google OAuth web client ID in server/.env');
}
if (!MONGO_URI) {
  throw new Error('Set MONGO_URI to the MongoDB connection string from Atlas in server/.env');
}
if (MONGO_DNS_SERVERS) {
  dns.setServers(MONGO_DNS_SERVERS.split(',').map(server => server.trim()).filter(Boolean));
}

const mongoUri = MONGO_URI.trim();
const keyBytes = Buffer.from(ENC_KEY, 'hex');
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const supabaseAdmin = SUPABASE_URL && SUPABASE_SECRET_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
    auth: { autoRefreshToken: false, persistSession: false }
  })
  : null;
const origins = ORIGIN.split(',').map(value => value.trim()).filter(Boolean);
const publicUser = user => ({ id: user.id, username: user.username, displayName: user.displayName, avatarUrl: user.avatarUrl });
const currentUser = user => ({
  ...publicUser(user),
  email: user.email,
  activeStatus: user.activeStatus,
  lastSeenAt: user.lastSeenAt,
  theme: user.theme
});
const chatKey = (first, second) => [String(first), String(second)].sort().join(':');
const encrypt = value => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBytes, iv);
  const encrypted = Buffer.concat([cipher.update(value), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]);
};
const decrypt = value => {
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBytes, value.subarray(0, 12));
  decipher.setAuthTag(value.subarray(12, 28));
  return Buffer.concat([decipher.update(value.subarray(28)), decipher.final()]);
};
const messageResponse = message => ({
  id: message.id,
  chat: message.chat && String(message.chat),
  from: String(message.from),
  to: message.to && String(message.to),
  group: message.group && String(message.group),
  kind: message.kind,
  text: message.deleted
    ? 'This message was deleted'
    : message.ct ? decrypt(message.ct).toString() : message.content,
  content: message.deleted ? '' : message.content,
  mediaUrl: message.mediaUrl,
  status: message.status,
  readBy: (message.readBy || []).map(String),
  edited: message.edited,
  deleted: message.deleted,
  at: message.createdAt
});
const signToken = user => jwt.sign(
  { id: user.id },
  JWT_SECRET,
  { algorithm: 'HS256', expiresIn: '30d', issuer: 'chatapp', audience: 'chatapp-api' }
);
const setAuthCookie = (res, token) => res.cookie('chat_token', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'none',
  path: '/',
  maxAge: 30 * 24 * 60 * 60 * 1000
});
const httpError = (status, message) => Object.assign(new Error(message), { status });
const requireObjectId = (value, label = 'id') => {
  if (!mongoose.isValidObjectId(value)) throw httpError(400, `Invalid ${label}`);
  return String(value);
};
const asyncRoute = handler => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
const normalizeUsername = value => String(value || '').toLowerCase().replace(/^@/, '');

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(cors({ origin: origins, credentials: true }));
app.use(cookieParser());
app.use(express.json({ limit: '100kb' }));
app.get('/healthz', (req, res) => res.json({ ok: mongoose.connection.readyState === 1 }));

const auth = (req, res, next) => {
  const header = req.get('authorization') || '';
  const token = req.cookies?.chat_token || /^Bearer\s+(.+)$/i.exec(header)?.[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'chatapp',
      audience: 'chatapp-api'
    });
    if (typeof payload === 'string' || typeof payload.id !== 'string' || !mongoose.isValidObjectId(payload.id)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    req.uid = payload.id;
    return next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
};

const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts; try again later' }
});
const connectedClients = new Map();
const online = connectedClients;
const rooms = new Map();
const callSockets = new Map();
const reconnectTimers = new Map();
const CALL_RECONNECT_GRACE_MS = 45_000;
const active = new Set();
const ownsCallSocket = (room, uid, socket) => callSockets.get(`${room}:${uid}`) === socket;
const send = (id, data) => {
  online.get(String(id))?.forEach(socket => {
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(data));
  });
};
const endCall = async (room, endReason = 'ended') => {
  const participants = rooms.get(room) || new Set();
  rooms.delete(room);
  for (const [key, timer] of reconnectTimers) {
    if (key.startsWith(`${room}:`)) {
      clearTimeout(timer);
      reconnectTimers.delete(key);
    }
  }
  for (const key of callSockets.keys()) {
    if (key.startsWith(`${room}:`)) callSockets.delete(key);
  }
  const call = await Call.findOneAndUpdate(
    { room, endedAt: { $exists: false } },
    { $set: { endedAt: new Date(), joined: [], endReason } },
    { new: true }
  ).select('members chat chatKey group');
  const recipients = new Set([
    ...participants,
    ...(call?.members || []).map(String)
  ]);
  recipients.forEach(id => send(id, {
    t: 'call-ended',
    room,
    chat: call?.chatKey || (call?.chat && String(call.chat)),
    group: call?.group && String(call.group)
  }));
};
const presence = (id, isOnline, lastSeenAt) => {
  if (isOnline) active.add(String(id));
  else active.delete(String(id));
  online.forEach((_, recipient) => {
    send(recipient, {
      type: 'PRESENCE',
      status: isOnline ? 'ONLINE' : 'OFFLINE',
      userId: String(id),
      lastSeenAt: lastSeenAt || null
    });
    send(recipient, { t: 'presence', id: String(id), on: isOnline, lastSeenAt: lastSeenAt || null });
  });
};
const chatMemberIds = chat => chat.members.map(member => String(member.user));
const chatMember = (chat, userId) => chat.members.find(member => String(member.user) === String(userId));
const ensureChat = (key, kind, members, group) => Chat.findOneAndUpdate(
  { key },
  {
    $setOnInsert: {
      key,
      kind,
      members: members.map(user => ({ user })),
      ...(group ? { group } : {})
    }
  },
  { upsert: true, new: true, runValidators: true }
);
const groupMembers = async groupId => {
  const group = await Group.findById(groupId).select('members');
  if (!group) throw httpError(404, 'Group not found');
  return group.members.map(String);
};
const notifyMessageParticipants = async message => {
  const recipients = message.group
    ? await groupMembers(message.group)
    : [String(message.from), String(message.to)];
  recipients.forEach(id => send(id, { t: 'upd', m: messageResponse(message) }));
};
const notifyMessageSender = message => send(String(message.from), { t: 'upd', m: messageResponse(message) });
const backfillChats = async () => {
  const migratedChatIds = new Set();
  const storedChats = await Chat.collection.find({}).toArray();
  for (const storedChat of storedChats) {
    const legacyMembers = (storedChat.members || []).filter(member => member?.toHexString);
    if (legacyMembers.length) {
      migratedChatIds.add(String(storedChat._id));
      await Chat.collection.updateOne(
        { _id: storedChat._id },
        {
          $set: {
            members: storedChat.members.map(member => member?.toHexString
              ? { user: member, unreadCount: 0 }
              : member)
          }
        }
      );
    }
  }
  const groups = await Group.find().select('_id members');
  for (const group of groups) {
    const chat = await ensureChat(String(group.id), 'group', group.members, group.id);
    const result = await Message.collection.updateMany(
      { chat: String(group.id) },
      { $set: { chat: chat._id } }
    );
    if (result.modifiedCount) migratedChatIds.add(String(chat.id));
  }
  const directChats = await Message.aggregate([
    { $match: { chat: { $type: 'string' }, group: null, to: { $ne: null } } },
    { $group: { _id: '$chat', senders: { $addToSet: '$from' }, recipients: { $addToSet: '$to' } } }
  ]);
  for (const chat of directChats) {
    const members = [...new Set([...chat.senders, ...chat.recipients].map(String))];
    const chatDoc = await ensureChat(chat._id, 'direct', members);
    await Message.collection.updateMany({ chat: chat._id }, { $set: { chat: chatDoc._id } });
    migratedChatIds.add(String(chatDoc.id));
  }
  for (const id of migratedChatIds) {
    const chat = await Chat.findById(id);
    if (!chat) continue;
    await Promise.all(chat.members.map(async member => {
      const userId = String(member.user);
      const unreadCount = await Message.countDocuments({
        chat: chat._id,
        from: { $ne: userId },
        status: { $ne: 'seen' }
      });
      await Chat.updateOne(
        { _id: chat._id, 'members.user': userId },
        { $set: { 'members.$.unreadCount': unreadCount } }
      );
    }));
  }
  const legacyCalls = await Call.collection.find({ chat: { $type: 'string' } }).toArray();
  for (const call of legacyCalls) {
    const chatDoc = await Chat.findOne({ key: call.chat });
    if (chatDoc) {
      await Call.collection.updateOne(
        { _id: call._id },
        { $set: { chatKey: call.chat, chat: chatDoc._id } }
      );
    }
  }
};

app.post('/api/auth/google', authRateLimit, asyncRoute(async (req, res) => {
  const credential = req.body?.credential;
  if (typeof credential !== 'string' || credential.length > 8192) {
    throw httpError(400, 'Google credential is required');
  }
  let ticket;
  try {
    ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
  } catch {
    throw httpError(401, 'Invalid Google credential');
  }
  const claims = ticket.getPayload();
  if (!claims?.sub || !claims.email || claims.email_verified !== true) {
    throw httpError(401, 'A verified Google account is required');
  }

  const email = claims.email.toLowerCase();
  let user = await User.findOne({ googleSub: claims.sub });
  if (!user) {
    const existing = await User.findOne({ email });
    if (existing) throw httpError(409, 'This email belongs to an account that needs secure migration');
    user = await User.create({
      email,
      googleSub: claims.sub,
      emailVerified: true,
      displayName: String(claims.name || email.split('@')[0]).slice(0, 40),
      avatarUrl: claims.picture
    });
  }
  const token = signToken(user);
  setAuthCookie(res, token);
  res.json({ token, user: currentUser(user) });
}));

app.post('/api/auth/setup', auth, asyncRoute(async (req, res) => {
  const user = await User.findById(req.uid);
  if (!user) throw httpError(404, 'User not found');
  if (user.username) throw httpError(409, 'Profile is already set up');
  const username = normalizeUsername(req.body?.username);
  const displayName = String(req.body?.displayName || username).trim().slice(0, 40);
  const password = req.body?.password;
  if (!/^[a-z0-9_]{3,20}$/.test(username)) {
    throw httpError(400, 'Username must be 3-20 letters, numbers, or underscores');
  }
  if (typeof password !== 'string' || password.length < 12 || password.length > 128) {
    throw httpError(400, 'Password must be between 12 and 128 characters');
  }
  user.username = username;
  user.displayName = displayName || username;
  user.passwordHash = await bcrypt.hash(password, 12);
  await user.save();
  res.json({ user: currentUser(user) });
}));

app.post('/api/auth/login', authRateLimit, asyncRoute(async (req, res) => {
  const username = normalizeUsername(req.body?.username);
  const password = req.body?.password;
  if (typeof password !== 'string' || password.length > 128) {
    throw httpError(401, 'Invalid username or password');
  }
  const user = await User.findOne({ username }).select('+passwordHash');
  if (!user?.passwordHash || !await bcrypt.compare(password, user.passwordHash)) {
    throw httpError(401, 'Invalid username or password');
  }
  const token = signToken(user);
  setAuthCookie(res, token);
  res.json({ token, user: currentUser(user) });
}));

app.post('/api/auth/check-username', authRateLimit, asyncRoute(async (req, res) => {
  const username = normalizeUsername(req.body?.username);
  if (!/^[a-z0-9_]{3,20}$/.test(username)) {
    throw httpError(400, 'Username must be 3-20 letters, numbers, or underscores');
  }
  const exists = await User.exists({ username });
  res.json({ exists: Boolean(exists) });
}));

app.get('/api/me', auth, asyncRoute(async (req, res) => {
  const user = await User.findById(req.uid);
  if (!user) throw httpError(404, 'User not found');
  res.json(currentUser(user));
}));

app.patch('/api/me', auth, asyncRoute(async (req, res) => {
  const user = await User.findById(req.uid);
  if (!user) throw httpError(404, 'User not found');
  const { displayName, activeStatus, theme } = req.body || {};
  if (displayName !== undefined) {
    if (typeof displayName !== 'string' || !displayName.trim() || displayName.length > 40) {
      throw httpError(400, 'Display name must be 1-40 characters');
    }
    user.displayName = displayName.trim();
  }
  if (activeStatus !== undefined) {
    if (typeof activeStatus !== 'boolean') throw httpError(400, 'activeStatus must be a boolean');
    user.activeStatus = activeStatus;
    if (!activeStatus) user.lastSeenAt = new Date();
  }
  if (theme !== undefined) {
    if (!theme || typeof theme !== 'object' || Array.isArray(theme)) throw httpError(400, 'Invalid theme');
    user.theme = {
      accent: /^#[0-9a-f]{6}$/i.test(theme.accent) ? theme.accent : user.theme.accent,
      wallpaper: ['dark', 'light'].includes(theme.wallpaper) ? theme.wallpaper : user.theme.wallpaper
    };
  }
  await user.save();
  presence(user.id, user.activeStatus && online.has(user.id), user.lastSeenAt);
  res.json(currentUser(user));
}));

app.get('/api/users/search', auth, asyncRoute(async (req, res) => {
  const username = String(req.query.q || '').toLowerCase().replace(/^@/, '');
  if (!/^[a-z0-9_]{3,20}$/.test(username)) return res.json([]);
  const users = await User.find({
    username,
    _id: { $ne: req.uid }
  }).select('username displayName avatarUrl').limit(10);
  res.json(users.map(publicUser));
}));

app.get('/api/chats', auth, asyncRoute(async (req, res) => {
  const chats = await Chat.find({ 'members.user': req.uid })
    .sort({ lastMessageAt: -1, updatedAt: -1 }).limit(100);
  const messageIds = chats.map(chat => chat.lastMessage).filter(Boolean);
  const latestMessages = messageIds.length ? await Message.find({ _id: { $in: messageIds } }) : [];
  const messageById = new Map(latestMessages.map(message => [String(message.id), messageResponse(message)]));
  const peerIds = [...new Set(chats.filter(chat => chat.kind === 'direct')
    .flatMap(chat => chatMemberIds(chat).filter(id => id !== req.uid)))];
  const users = await User.find({ _id: { $in: peerIds } }).select('username displayName avatarUrl');
  const groupIds = chats.filter(chat => chat.kind === 'group').map(chat => chat.group);
  const groups = await Group.find({ _id: { $in: groupIds } })
    .populate('members', 'username displayName avatarUrl');
  res.json({
    users: users.map(publicUser),
    groups: groups.map(group => ({
      id: group.id,
      name: group.name,
      members: group.members.map(publicUser)
    })),
    chats: chats.map(chat => ({
      id: chat.group ? String(chat.group) : chatMemberIds(chat).find(id => id !== req.uid),
      chatId: String(chat.id),
      kind: chat.kind,
      members: chatMemberIds(chat),
      group: chat.group && String(chat.group),
      lastMessageAt: chat.lastMessageAt,
      lastMessage: chat.lastMessage ? messageById.get(String(chat.lastMessage)) || null : null,
      unreadCount: chatMember(chat, req.uid)?.unreadCount || 0
    }))
  });
}));

app.post('/api/groups', auth, asyncRoute(async (req, res) => {
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const names = req.body?.usernames;
  if (!name || name.length > 80 || !Array.isArray(names) || names.length < 1 || names.length > 99) {
    throw httpError(400, 'Provide a group name and 1-99 member usernames');
  }
  const normalized = [...new Set(names.map(normalizeUsername))].filter(Boolean);
  const users = await User.find({ username: { $in: normalized } }).select('_id');
  if (users.length !== normalized.length || normalized.length !== names.length) {
    throw httpError(400, 'One or more usernames are invalid');
  }
  const members = [...new Set([req.uid, ...users.map(user => String(user.id))])];
  const group = await Group.create({ name, owner: req.uid, admins: [req.uid], members });
  await ensureChat(String(group.id), 'group', members, group.id);
  res.status(201).json({ id: group.id });
}));

app.get('/api/messages/:id', auth, asyncRoute(async (req, res) => {
  let chat;
  let groupChat = false;
  if (req.query.g) {
    const groupId = requireObjectId(req.query.g, 'group id');
    const group = await Group.exists({ _id: groupId, members: req.uid });
    if (!group || groupId !== req.params.id) throw httpError(403, 'Forbidden');
    chat = groupId;
    groupChat = true;
  } else {
    const peerId = requireObjectId(req.params.id, 'user id');
    if (peerId === req.uid || !await User.exists({ _id: peerId })) throw httpError(404, 'Chat not found');
    chat = chatKey(req.uid, peerId);
  }
  const chatDoc = groupChat
    ? await Chat.findOne({ key: chat })
    : await ensureChat(chat, 'direct', [req.uid, req.params.id]);
  if (!chatDoc || !chatMember(chatDoc, req.uid)) throw httpError(403, 'Forbidden');
  const filter = { chat: chatDoc._id };
  if (req.query.before !== undefined) {
    const before = new Date(String(req.query.before));
    if (Number.isNaN(before.getTime())) throw httpError(400, 'Invalid before timestamp');
    filter.createdAt = { $lt: before };
  }
  const messages = await Message.find(filter).sort({ createdAt: -1 }).limit(100);
  const undelivered = messages.filter(message => message.status === 'sent' && (
    groupChat ? String(message.from) !== req.uid : String(message.to) === req.uid
  ));
  if (undelivered.length) {
    await Message.updateMany(
      {
        _id: { $in: undelivered.map(message => message.id) },
        ...(groupChat ? { from: { $ne: req.uid } } : { to: req.uid }),
        status: 'sent'
      },
      { $set: { status: 'delivered' } }
    );
    undelivered.forEach(message => {
      message.status = 'delivered';
      notifyMessageSender(message);
    });
  }
  res.json(messages.reverse().map(messageResponse));
}));

app.get('/api/calls/missed', auth, asyncRoute(async (req, res) => {
  const calls = await Call.find({
    members: req.uid,
    createdBy: { $ne: req.uid },
    answeredAt: { $exists: false },
    endedAt: { $exists: true },
    endReason: { $ne: 'declined' }
  }).sort({ createdAt: -1 }).limit(100).select('room createdBy video createdAt');
  const callers = await User.find({ _id: { $in: calls.map(call => call.createdBy) } }).select('_id username displayName');
  const callerById = new Map(callers.map(caller => [String(caller.id), caller]));
  res.json(calls.map(call => {
    const caller = callerById.get(String(call.createdBy));
    return {
      id: call.id,
      room: call.room,
      username: caller?.username,
      fromName: caller?.displayName || 'Metufy contact',
      video: call.video,
      at: call.createdAt
    };
  }));
}));

app.get('/api/calls/:id', auth, asyncRoute(async (req, res) => {
  let chat;
  let groupId;
  if (req.query.g) {
    groupId = requireObjectId(req.query.g, 'group id');
    if (groupId !== req.params.id || !await Group.exists({ _id: groupId, members: req.uid })) {
      throw httpError(403, 'Forbidden');
    }
    chat = groupId;
  } else {
    const peerId = requireObjectId(req.params.id, 'user id');
    if (peerId === req.uid || !await User.exists({ _id: peerId })) throw httpError(404, 'Chat not found');
    chat = chatKey(req.uid, peerId);
  }

  const chatDoc = await ensureChat(
    chat,
    groupId ? 'group' : 'direct',
    groupId ? await groupMembers(groupId) : [req.uid, String(req.params.id)],
    groupId
  );
  const callFilter = {
    chat: chatDoc._id,
    chatKey: chat,
    ...(groupId ? { group: groupId } : { group: { $exists: false }, members: { $all: [req.uid, String(req.params.id)] } })
  };
  const calls = await Call.find(callFilter)
    .sort({ createdAt: -1 })
    .limit(100);
  const memberIds = [...new Set(calls.flatMap(call => call.members.map(String)))];
  const users = await User.find({ _id: { $in: memberIds } }).select('username displayName');
  const userById = new Map(users.map(user => [String(user.id), {
    id: String(user.id),
    username: user.username,
    displayName: user.displayName
  }]));
  res.json(calls.reverse().map(call => ({
    id: call.id,
    room: call.room,
    createdBy: String(call.createdBy),
    members: call.members.map(member => userById.get(String(member))).filter(Boolean),
    video: call.video,
    at: call.createdAt,
    answeredAt: call.answeredAt,
    endedAt: call.endedAt,
    endReason: call.endReason
  })));
}));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024, files: 1 }
});
const allowedMime = /^(image\/(jpeg|png|gif|webp|avif)|audio\/(webm|ogg|mpeg|wav|mp4))$/i;
app.post('/api/upload', auth, upload.single('file'), asyncRoute(async (req, res) => {
  if (!req.file || !allowedMime.test(req.file.mimetype)) {
    throw httpError(400, 'Upload a supported image or audio file');
  }
  const media = await Media.create({
    owner: req.uid,
    access: [req.uid],
    mime: req.file.mimetype,
    ct: encrypt(req.file.buffer)
  });
  res.status(201).json({ id: media.id });
}));

app.post('/api/media/upload-url', auth, asyncRoute(async (req, res) => {
  if (!supabaseAdmin) throw httpError(503, 'Supabase Storage is not configured');
  const { folder, mime, size } = req.body || {};
  const uploadFolder = folder || 'conversations';
  if (!['conversations', 'profiles'].includes(uploadFolder)) {
    throw httpError(400, 'folder must be conversations or profiles');
  }
  if (typeof mime !== 'string' || !/^image\/(jpeg|png|webp|avif)$/i.test(mime) ||
      !Number.isInteger(size) || size < 1 || size > 500_000) {
    throw httpError(400, 'Image must be no larger than 500,000 bytes');
  }
  const extension = ({ 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/avif': 'avif' })[mime.toLowerCase()];
  const fileKey = `${uploadFolder}/${req.uid}/${crypto.randomUUID()}.${extension}`;
  const { data, error } = await supabaseAdmin.storage.from('metufy')
    .createSignedUploadUrl(fileKey, { upsert: false });
  if (error) throw httpError(502, `Could not prepare media upload: ${error.message}`);
  res.json({ fileKey, token: data.token });
}));

app.post('/api/media/complete', auth, asyncRoute(async (req, res) => {
  if (!supabaseAdmin) throw httpError(503, 'Supabase Storage is not configured');
  const { folder, fileKey, mime, size } = req.body || {};
  const uploadFolder = folder || 'conversations';
  const keyPattern = new RegExp(`^${uploadFolder}/${req.uid}/[0-9a-f-]{36}\\.(jpg|png|webp|avif)$`);
  if (!['conversations', 'profiles'].includes(uploadFolder) ||
      typeof fileKey !== 'string' || !keyPattern.test(fileKey) ||
      typeof mime !== 'string' || !Number.isInteger(size) ||
      size < 1 || size > 500_000) {
    throw httpError(400, 'Invalid uploaded media metadata');
  }
  const slash = fileKey.lastIndexOf('/');
  const storageFolder = fileKey.slice(0, slash);
  const filename = fileKey.slice(slash + 1);
  const bucket = supabaseAdmin.storage.from('metufy');
  const { data: files, error } = await bucket
    .list(storageFolder, { search: filename, limit: 10 });
  if (error) throw httpError(502, `Could not verify media upload: ${error.message}`);
  const uploadedFile = files.find(file => file.name === filename);
  if (!uploadedFile || uploadedFile.metadata?.size !== size ||
      uploadedFile.metadata?.size > 500_000 ||
      uploadedFile.metadata?.mimetype !== mime) {
    if (uploadedFile) {
      const { error: cleanupError } = await bucket.remove([fileKey]);
      if (cleanupError) console.error('Rejected Supabase upload cleanup failed:', cleanupError.message);
    }
    throw httpError(400, 'Uploaded file metadata does not match');
  }
  const existing = await Media.findOne({ owner: req.uid, fileKey });
  if (existing) {
    if (uploadFolder === 'profiles') {
      await User.updateOne({ _id: req.uid }, { $set: { avatarUrl: existing.url } });
    }
    return res.status(200).json({
      id: existing.id,
      fileKey: existing.fileKey,
      url: existing.url,
      mime: existing.mime,
      size: existing.size,
      folder: uploadFolder
    });
  }
  const { data: publicData } = bucket.getPublicUrl(fileKey);
  const media = await Media.create({
    owner: req.uid,
    fileKey,
    url: publicData.publicUrl,
    mime,
    size
  });
  if (uploadFolder === 'profiles') {
    await User.updateOne({ _id: req.uid }, { $set: { avatarUrl: media.url } });
  }
  res.status(201).json({
    id: media.id,
    fileKey: media.fileKey,
    url: media.url,
    mime: media.mime,
    size: media.size,
    folder: uploadFolder
  });
}));

app.get('/api/media/:id', auth, asyncRoute(async (req, res) => {
  const id = requireObjectId(req.params.id, 'media id');
  const media = await Media.findOne({ _id: id, access: req.uid });
  if (!media) throw httpError(404, 'Media not found');
  res.type(media.mime).set('Cache-Control', 'private, no-store').send(decrypt(media.ct));
}));

const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });

wss.on('connection', async (socket, req) => {
  const uid = req.user?.id;
  if (!uid) return socket.close(4001, 'Unauthorized');

  try {
    const user = await User.findById(uid);
    if (!user) return socket.close(4001, 'Unauthorized');
    const alreadyConnected = online.has(uid) && online.get(uid).size > 0;
    if (!online.has(uid)) online.set(uid, new Set());
    online.get(uid).add(socket);
    if (user.activeStatus && !alreadyConnected) presence(uid, true, user.lastSeenAt);
    socket.send(JSON.stringify({ t: 'online', ids: [...active] }));

    const handle = async event => {
      if (!event || typeof event !== 'object' || Array.isArray(event) ||
          (typeof event.t !== 'string' && typeof event.type !== 'string')) {
        throw httpError(400, 'Invalid event');
      }
      switch (event.type || event.t) {
        case 'SEND_MESSAGE': {
          const clientId = event.clientId;
          const kind = event.kind || 'text';
          const content = event.content ?? event.text ?? '';
          if (!['text', 'image', 'audio', 'video', 'file'].includes(kind) ||
              typeof content !== 'string' || content.length > 4000) {
            throw httpError(400, 'Invalid message');
          }
          if (clientId !== undefined && (typeof clientId !== 'string' || !clientId || clientId.length > 128)) {
            throw httpError(400, 'Invalid message identifier');
          }
          let chatDoc;
          const chatId = event.chatId || event.targetChatId || event.chat;
          if (typeof chatId === 'string' && mongoose.isValidObjectId(chatId)) {
            chatDoc = await Chat.findById(chatId);
            if (!chatDoc) chatDoc = await Chat.findOne({ key: chatId });
            if (!chatDoc && chatId !== uid && await User.exists({ _id: chatId })) {
              chatDoc = await ensureChat(chatKey(uid, chatId), 'direct', [uid, chatId]);
            }
          } else if (typeof chatId === 'string') {
            chatDoc = await Chat.findOne({ key: chatId });
          }
          if (!chatDoc || !chatMember(chatDoc, uid)) throw httpError(403, 'Forbidden');
          if (kind === 'text' && !content.trim()) throw httpError(400, 'Message cannot be empty');
          let mediaUrl;
          if (kind !== 'text') {
            if (typeof event.mediaUrl !== 'string' || event.mediaUrl.length > 2048) {
              throw httpError(400, 'A valid mediaUrl is required');
            }
            let parsedUrl;
            try {
              parsedUrl = new URL(event.mediaUrl);
            } catch {
              throw httpError(400, 'Invalid mediaUrl');
            }
            if (parsedUrl.protocol !== 'https:') throw httpError(400, 'Media URL must use HTTPS');
            const media = await Media.findOne({ owner: uid, url: parsedUrl.href }).select('mime');
            if (!media || (kind === 'image' && !media.mime.startsWith('image/')) ||
                (kind === 'audio' && !media.mime.startsWith('audio/')) ||
                (kind === 'video' && !media.mime.startsWith('video/'))) {
              throw httpError(400, 'Media must be uploaded by the sender before messaging');
            }
            mediaUrl = parsedUrl.href;
          }
          if (clientId) {
            const previous = await Message.findOne({ from: uid, clientId });
            if (previous) {
              socket.send(JSON.stringify({
                type: 'SEND_MESSAGE_ACK',
                messageId: previous.id,
                clientId,
                message: messageResponse(previous)
              }));
              break;
            }
          }
          const recipients = chatMemberIds(chatDoc);
          const peerId = recipients.find(id => id !== uid);
          let message;
          try {
            message = await Message.create({
              chat: chatDoc._id,
              from: uid,
              to: chatDoc.kind === 'direct' ? peerId : undefined,
              group: chatDoc.group,
              clientId,
              kind,
              content: kind === 'text' ? content : '',
              mediaUrl,
              readBy: [uid],
              status: 'sent'
            });
          } catch (error) {
            if (error.code !== 11000 || !clientId) throw error;
            message = await Message.findOne({ from: uid, clientId });
            if (!message) throw error;
            socket.send(JSON.stringify({
              type: 'SEND_MESSAGE_ACK',
              messageId: message.id,
              clientId,
              message: messageResponse(message)
            }));
            break;
          }
          await Chat.updateOne(
            { _id: chatDoc._id },
            { $set: { lastMessage: message.id, lastMessageAt: message.createdAt } }
          );
          await Promise.all(recipients.filter(id => id !== uid && !active.has(id)).map(id =>
            Chat.updateOne(
              { _id: chatDoc._id, 'members.user': id },
              { $inc: { 'members.$.unreadCount': 1 } }
            )
          ));
          const payload = {
            ...messageResponse(message),
            chatId: String(chatDoc.id),
            createdAt: message.createdAt
          };
          socket.send(JSON.stringify({
            type: 'SEND_MESSAGE_ACK',
            messageId: message.id,
            clientId,
            message: payload
          }));
          recipients.filter(id => id !== uid && active.has(id)).forEach(id =>
            send(id, { type: 'MESSAGE', message: payload })
          );
          break;
        }
        case 'MARK_READ': {
          const chatId = event.chatId || event.targetChatId || event.chat;
          let chatDoc;
          if (typeof chatId === 'string' && mongoose.isValidObjectId(chatId)) {
            chatDoc = await Chat.findById(chatId);
            if (!chatDoc) chatDoc = await Chat.findOne({ key: chatId });
            if (!chatDoc && chatId !== uid && await User.exists({ _id: chatId })) {
              chatDoc = await ensureChat(chatKey(uid, chatId), 'direct', [uid, chatId]);
            }
          } else if (typeof chatId === 'string') {
            chatDoc = await Chat.findOne({ key: chatId });
          }
          if (!chatDoc || !chatMember(chatDoc, uid)) throw httpError(403, 'Forbidden');
          const lastReadMessageAt = new Date();
          await Chat.updateOne(
            { _id: chatDoc._id, 'members.user': uid },
            { $set: { 'members.$.unreadCount': 0, 'members.$.lastReadMessageAt': lastReadMessageAt } }
          );
          await Message.updateMany(
            { chat: chatDoc._id, from: { $ne: uid } },
            { $addToSet: { readBy: uid }, $set: { status: 'seen' } }
          );
          const senders = await Message.distinct('from', { chat: chatDoc._id, from: { $ne: uid } });
          senders.forEach(sender => send(String(sender), {
            type: 'MESSAGES_READ',
            chatId: String(chatDoc.id),
            userId: uid,
            lastReadMessageAt
          }));
          break;
        }
        case 'WEBRTC_SIGNAL': {
          const room = event.room;
          const peerId = requireObjectId(event.to || event.targetUserId, 'recipient id');
          if (typeof room !== 'string' || !ownsCallSocket(room, uid, socket) ||
              !rooms.get(room)?.has(uid) || !rooms.get(room)?.has(peerId)) {
            throw httpError(403, 'Both call participants must have joined');
          }
          if (!await Call.exists({ room, members: { $all: [uid, peerId] }, endedAt: { $exists: false } })) {
            throw httpError(403, 'Call not found');
          }
          const signal = event.signal || event.sdp || event.candidate;
          if (!signal || typeof signal !== 'object') throw httpError(400, 'Invalid WebRTC signal');
          send(peerId, { type: 'WEBRTC_SIGNAL', from: uid, room, signal });
          break;
        }
        case 'msg': {
          const kind = event.kind || 'text';
          if (!['text', 'image', 'audio', 'video', 'file'].includes(kind) ||
              typeof event.text !== 'string' || event.text.length > 4000) {
            throw httpError(400, 'Invalid message');
          }
          if (event.clientId !== undefined && (typeof event.clientId !== 'string' || event.clientId.length > 128)) {
            throw httpError(400, 'Invalid message identifier');
          }
          if (event.clientId) {
            const previous = await Message.findOne({ from: uid, clientId: event.clientId });
            if (previous) {
              send(uid, { t: 'stored', clientId: event.clientId, m: messageResponse(previous) });
              break;
            }
          }
          let recipients;
          let chat;
          let groupId;
          if (event.group) {
            groupId = requireObjectId(event.group, 'group id');
            const group = await Group.findOne({ _id: groupId, members: uid }).select('members');
            if (!group) throw httpError(403, 'Forbidden');
            recipients = group.members.map(String);
            chat = groupId;
          } else {
            const peerId = requireObjectId(event.to, 'recipient id');
            if (peerId === uid || !await User.exists({ _id: peerId })) throw httpError(404, 'Recipient not found');
            recipients = [uid, peerId];
            chat = chatKey(uid, peerId);
          }

          let content = event.text;
          let media;
          if (kind === 'text') {
            if (!content.trim()) throw httpError(400, 'Message cannot be empty');
          } else {
            const mediaId = requireObjectId(content, 'media id');
            media = await Media.findOne({ _id: mediaId, owner: uid });
            if (!media || (kind === 'image' && !media.mime.startsWith('image/')) ||
                (kind === 'audio' && !media.mime.startsWith('audio/')) ||
                (kind === 'video' && !media.mime.startsWith('video/'))) {
              throw httpError(400, 'Invalid media attachment');
            }
            content = mediaId;
            await Media.updateOne({ _id: mediaId }, { $addToSet: { access: { $each: recipients } } });
          }

          const chatDoc = await ensureChat(chat, groupId ? 'group' : 'direct', recipients, groupId);
          let message, inserted = true;
          try {
            message = await Message.create({
              chat: chatDoc._id,
              from: uid,
              to: groupId ? undefined : recipients.find(recipient => recipient !== uid),
              group: groupId,
              clientId: event.clientId,
              kind,
              content: '',
              ct: encrypt(Buffer.from(content)),
              readBy: [uid],
              status: 'sent'
            });
          } catch (error) {
            if (error.code !== 11000 || !event.clientId) throw error;
            message = await Message.findOne({ from: uid, clientId: event.clientId });
            if (!message) throw error;
            inserted = false;
          }
          if (inserted) {
            await Chat.updateOne(
              { _id: chatDoc._id },
              { $set: { lastMessage: message.id, lastMessageAt: message.createdAt } }
            );
            await Promise.all(recipients.filter(id => id !== uid && !active.has(id)).map(id =>
              Chat.updateOne(
                { _id: chatDoc._id, 'members.user': id },
                { $inc: { 'members.$.unreadCount': 1 } }
              )
            ));
          }
          recipients.forEach(recipient => send(recipient, { t: 'msg', m: messageResponse(message) }));
          if (typeof event.clientId === 'string') {
            send(uid, { t: 'stored', clientId: event.clientId, m: messageResponse(message) });
          }
          break;
        }
        case 'delivered': {
          const messageId = requireObjectId(event.id, 'message id');
          const message = await Message.findOne({ _id: messageId, status: 'sent' });
          if (message) {
            const isRecipient = message.group
              ? await Group.exists({ _id: message.group, members: uid })
              : String(message.to) === uid;
            if (!isRecipient) throw httpError(403, 'Forbidden');
            message.status = 'delivered';
            await message.save();
            notifyMessageSender(message);
          }
          break;
        }
        case 'seen': {
          if (event.group) {
            const groupId = requireObjectId(event.group, 'group id');
            const members = await groupMembers(groupId);
            if (!members.includes(uid)) throw httpError(403, 'Forbidden');
            const chatDoc = await Chat.findOne({ key: groupId });
            if (!chatDoc) throw httpError(404, 'Chat not found');
            await Chat.updateOne(
              { _id: chatDoc._id, 'members.user': uid },
              { $set: { 'members.$.unreadCount': 0, 'members.$.lastReadMessageAt': new Date() } }
            );
            await Message.updateMany(
              { chat: chatDoc._id, from: { $ne: uid }, status: { $ne: 'seen' } },
              { $set: { status: 'seen' }, $addToSet: { readBy: uid } }
            );
            members.forEach(member => send(member, { t: 'seen', by: uid, group: groupId }));
          } else {
            const peerId = requireObjectId(event.chat, 'chat id');
            const directChat = await Chat.findOne({
              key: chatKey(uid, peerId),
              'members.user': { $all: [uid, peerId] }
            });
            if (!directChat) {
              throw httpError(403, 'Forbidden');
            }
            await Chat.updateOne(
              { _id: directChat._id, 'members.user': uid },
              { $set: { 'members.$.unreadCount': 0, 'members.$.lastReadMessageAt': new Date() } }
            );
            await Message.updateMany(
              { chat: directChat._id, to: uid, status: { $ne: 'seen' } },
              { $set: { status: 'seen' }, $addToSet: { readBy: uid } }
            );
            send(peerId, { t: 'seen', by: uid });
          }
          break;
        }
        case 'typing': {
          if (event.group) {
            const groupId = requireObjectId(event.group, 'group id');
            const members = await groupMembers(groupId);
            if (!members.includes(uid)) throw httpError(403, 'Forbidden');
            members.filter(member => member !== uid)
              .forEach(member => send(member, { t: 'typing', from: uid, group: groupId }));
          } else {
            const peerId = requireObjectId(event.to, 'recipient id');
            if (peerId === uid || !await User.exists({ _id: peerId })) throw httpError(404, 'Recipient not found');
            send(peerId, { t: 'typing', from: uid });
          }
          break;
        }
        case 'edit':
        case 'delete': {
          const messageId = requireObjectId(event.id, 'message id');
          const message = await Message.findOne({ _id: messageId, from: uid });
          if (!message || message.deleted) throw httpError(404, 'Message not found');
          if (event.t === 'edit') {
            if (message.kind !== 'text' || typeof event.text !== 'string' || !event.text.trim() || event.text.length > 4000) {
              throw httpError(400, 'Only non-empty text messages can be edited');
            }
            if (Date.now() - message.createdAt.getTime() > 5 * 60 * 1000) {
              throw httpError(403, 'Edit window (5 minutes) has passed');
            }
            message.ct = encrypt(Buffer.from(event.text));
            message.content = event.text;
            message.edited = true;
          } else {
            if (message.kind !== 'text') {
              if (message.ct) {
                const mediaId = decrypt(message.ct).toString();
                if (mongoose.isValidObjectId(mediaId)) await Media.deleteOne({ _id: mediaId, owner: uid });
              }
              message.mediaUrl = undefined;
              message.content = '';
            }
            if (message.ct) message.ct = encrypt(Buffer.alloc(0));
            message.content = '';
            message.deleted = true;
            message.kind = 'text';
          }
          await message.save();
          await notifyMessageParticipants(message);
          break;
        }
        case 'call-invite': {
          const room = event.room;
          if (typeof room !== 'string' || room.length < 8 || room.length > 128) {
            throw httpError(400, 'Invalid call room');
          }
          let recipients;
          let groupId;
          let callChat;
          if (event.group) {
            groupId = requireObjectId(event.group, 'group id');
            recipients = await groupMembers(groupId);
            if (!recipients.includes(uid)) throw httpError(403, 'Forbidden');
            callChat = groupId;
          } else {
            if (!Array.isArray(event.to) || event.to.length < 1 || event.to.length > 20) {
              throw httpError(400, 'Invalid call recipients');
            }
            recipients = [...new Set(event.to.map(id => requireObjectId(id, 'recipient id')))];
            if (recipients.includes(uid)) throw httpError(400, 'Cannot invite yourself');
            if (await User.countDocuments({ _id: { $in: recipients } }) !== recipients.length) {
              throw httpError(404, 'Call recipient not found');
            }
            recipients.unshift(uid);
            callChat = chatKey(uid, recipients.find(id => id !== uid));
          }
          const callChatDoc = await ensureChat(
            callChat,
            groupId ? 'group' : 'direct',
            recipients,
            groupId
          );
          const existingCall = await Call.findOne({ room });
          if (existingCall) throw httpError(409, 'Call room is unavailable');
          const call = await Call.create({
            room,
            chat: callChatDoc._id,
            chatKey: callChat,
            group: groupId,
            createdBy: uid,
            members: [...new Set(recipients)],
            joined: [uid],
            video: Boolean(event.video)
          });
          if (!rooms.has(room)) rooms.set(room, new Set([uid]));
          callSockets.set(`${room}:${uid}`, socket);
          recipients.forEach(id => send(id, { t: 'call-log', room, chat: callChat, group: groupId }));
          recipients.filter(id => id !== uid).forEach(id => send(id, {
            t: 'call-invite',
            from: uid,
            fromName: user.displayName,
            room,
            video: call.video,
            name: typeof event.name === 'string' ? event.name.slice(0, 80) : undefined,
            chatId: String(callChatDoc.id),
            ...(groupId ? { group: String(groupId) } : {})
          }));
          break;
        }
        case 'call-join': {
          const room = event.room;
          if (typeof room !== 'string' || room.length > 128) throw httpError(400, 'Invalid call room');
          const wasInRoom = rooms.get(room)?.has(uid) || false;
          const reconnectKey = `${room}:${uid}`;
          const priorSocket = callSockets.get(reconnectKey);
          const priorCall = await Call.findOne({ room, members: uid, endedAt: { $exists: false } }).select('joined');
          if (!priorCall) throw httpError(403, 'Call invite required');
          const wasPreviouslyJoined = priorCall.joined.some(member => String(member) === uid);
          const call = await Call.findOneAndUpdate(
            { room, members: uid, endedAt: { $exists: false } },
            { $addToSet: { joined: uid } },
            { new: true }
          );
          if (!call) throw httpError(403, 'Call invite required');
          clearTimeout(reconnectTimers.get(reconnectKey));
          reconnectTimers.delete(reconnectKey);
          const reconnected = wasPreviouslyJoined &&
            (!wasInRoom || (priorSocket !== undefined && priorSocket !== socket));
          if (String(call.createdBy) !== uid) {
            await Call.updateOne({ _id: call.id }, { $set: { answeredAt: new Date() } });
          }
          const participants = rooms.get(room) || new Set();
          if (reconnected && wasInRoom) {
            participants.forEach(id => {
              if (id !== uid) send(id, { t: 'call-left', room, id: uid });
            });
          }
          socket.send(JSON.stringify({ t: 'call-peers', room, ids: [...participants].filter(id => id !== uid) }));
          participants.add(uid);
          rooms.set(room, participants);
          callSockets.set(reconnectKey, socket);
          participants.forEach(id => {
            if (id !== uid) send(id, {
              t: 'call-joined',
              room,
              id: uid,
              ...(reconnected ? {
                reconnected: true,
                from: uid,
                fromName: user.displayName,
                fromUsername: user.username,
                chat: call.chatKey,
                group: call.group && String(call.group),
                at: new Date().toISOString()
              } : {})
            });
          });
          break;
        }
        case 'call-leave': {
          if (typeof event.room !== 'string') throw httpError(400, 'Invalid call room');
          if (ownsCallSocket(event.room, uid, socket) && rooms.get(event.room)?.has(uid)) {
            await endCall(event.room);
          }
          break;
        }
        case 'call-decline': {
          if (typeof event.room !== 'string') throw httpError(400, 'Invalid call room');
          if (await Call.exists({ room: event.room, members: uid, endedAt: { $exists: false } })) {
            await endCall(event.room, 'declined');
          }
          break;
        }
        case 'sig': {
          const room = event.room;
          const peerId = requireObjectId(event.to, 'recipient id');
          if (typeof room !== 'string' || !ownsCallSocket(room, uid, socket) ||
              !rooms.get(room)?.has(uid) || !rooms.get(room)?.has(peerId)) {
            throw httpError(403, 'Both call participants must have joined');
          }
          if (!await Call.exists({ room, members: { $all: [uid, peerId] }, endedAt: { $exists: false } })) {
            throw httpError(403, 'Call not found');
          }
          send(peerId, { t: 'sig', from: uid, room, d: event.d });
          break;
        }
        default:
          throw httpError(400, 'Unknown event type');
      }
    };

    let eventQueue = Promise.resolve();
    socket.on('message', raw => {
      eventQueue = eventQueue.then(async () => {
        let event;
        try {
          event = JSON.parse(raw.toString());
          await handle(event);
        } catch (error) {
          const response = {
            t: 'error',
            error: error.status ? error.message : 'Request failed',
            ...(typeof event?.clientId === 'string' ? { clientId: event.clientId } : {}),
            ...(typeof event?.type === 'string' || typeof event?.t === 'string'
              ? { eventType: event.type || event.t }
              : {}),
            ...(typeof event?.room === 'string' ? { room: event.room } : {})
          };
          if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(response));
          if (!error.status) console.error('WebSocket request failed:', error);
        }
      });
    });
    socket.on('close', async () => {
      online.get(uid)?.delete(socket);
      for (const [room, participants] of rooms) {
        const reconnectKey = `${room}:${uid}`;
        if (!participants.has(uid) || callSockets.get(reconnectKey) !== socket) continue;
        callSockets.delete(reconnectKey);
        participants.delete(uid);
        participants.forEach(id => send(id, { t: 'call-left', room, id: uid }));
        clearTimeout(reconnectTimers.get(reconnectKey));
        const timer = setTimeout(() => {
          reconnectTimers.delete(reconnectKey);
          if (rooms.get(room)?.has(uid)) return;
          void endCall(room).catch(error => console.error('Call recovery cleanup failed:', error));
        }, CALL_RECONNECT_GRACE_MS);
        reconnectTimers.set(reconnectKey, timer);
      }
      if (!online.get(uid)?.size) {
        online.delete(uid);
        const lastSeenAt = new Date();
        try {
          await User.updateOne({ _id: uid }, { $set: { lastSeenAt } });
          presence(uid, false, lastSeenAt);
        } catch (error) {
          console.error('Presence update failed:', error);
        }
      }
    });
  } catch (error) {
    console.error('WebSocket connection setup failed:', error);
    socket.close(1011, 'Connection setup failed');
  }
});

server.on('upgrade', (req, socket, head) => {
  const reject = (status, reason) => {
    socket.write(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\n\r\n`);
    socket.destroy();
  };
  const requestPath = (req.url || '').split('?')[0];
  if (requestPath !== '/ws') return reject(404, 'Not Found');
  const origin = req.headers.origin;
  if (origin && !origins.includes(origin)) return reject(403, 'Forbidden');
  try {
    const tokenCookie = (req.headers.cookie || '').split(';')
      .map(value => value.trim())
      .find(value => value.startsWith('chat_token='));
    const token = tokenCookie && decodeURIComponent(tokenCookie.slice('chat_token='.length));
    const payload = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'chatapp',
      audience: 'chatapp-api'
    });
    if (typeof payload === 'string' || typeof payload.id !== 'string' ||
        !mongoose.isValidObjectId(payload.id)) {
      return reject(401, 'Unauthorized');
    }
    req.user = { id: payload.id };
    wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
  } catch {
    reject(401, 'Unauthorized');
  }
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error instanceof multer.MulterError) {
    return res.status(error.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: 'Invalid upload' });
  }
  if (error.code === 11000) return res.status(409).json({ error: 'A record with that value already exists' });
  if (error.name === 'ValidationError' || error.name === 'CastError') {
    return res.status(400).json({ error: 'Invalid request data' });
  }
  if (error.status) return res.status(error.status).json({ error: error.message });
  console.error('Request failed:', error);
  return res.status(500).json({ error: 'Internal server error' });
});

mongoose.connect(mongoUri)
  .then(backfillChats)
  .then(() => server.listen(Number(PORT), () => console.log(`API + WS listening on port ${PORT}`)))
  .catch(error => {
    console.error('MongoDB connection failed:', error.message);
    process.exitCode = 1;
  });
