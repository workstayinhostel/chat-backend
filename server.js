import 'dotenv/config';
import http from 'node:http';
import crypto from 'node:crypto';
import dns from 'node:dns';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import multer from 'multer';
import { rateLimit } from 'express-rate-limit';
import { WebSocketServer, WebSocket } from 'ws';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import { User, Group, Chat, Message, Media, Call } from './models.js';

const {
  JWT_SECRET,
  ENC_KEY,
  MONGO_URI,
  MONGO_DNS_SERVERS,
  GOOGLE_CLIENT_ID,
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
const origins = ORIGIN.split(',').map(value => value.trim()).filter(Boolean);
const publicUser = user => ({ id: user.id, username: user.username, displayName: user.displayName, avatarUrl: user.avatarUrl });
const currentUser = user => ({
  ...publicUser(user),
  email: user.email,
  activeStatus: user.activeStatus,
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
  from: String(message.from),
  to: message.to && String(message.to),
  group: message.group && String(message.group),
  kind: message.kind,
  text: message.deleted ? 'This message was deleted' : decrypt(message.ct).toString(),
  status: message.status,
  edited: message.edited,
  deleted: message.deleted,
  at: message.createdAt
});
const signToken = user => jwt.sign(
  { id: user.id },
  JWT_SECRET,
  { algorithm: 'HS256', expiresIn: '30d', issuer: 'chatapp', audience: 'chatapp-api' }
);
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
app.use(cors({ origin: origins }));
app.use(express.json({ limit: '100kb' }));
app.get('/healthz', (req, res) => res.json({ ok: mongoose.connection.readyState === 1 }));

const auth = (req, res, next) => {
  const header = req.get('authorization') || '';
  const token = /^Bearer\s+(.+)$/i.exec(header)?.[1];
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
const online = new Map();
const rooms = new Map();
const active = new Set();
const send = (id, data) => {
  online.get(String(id))?.forEach(socket => {
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(data));
  });
};
const endCall = async (room, endReason = 'ended') => {
  const participants = rooms.get(room) || new Set();
  rooms.delete(room);
  const call = await Call.findOneAndUpdate(
    { room, endedAt: { $exists: false } },
    { $set: { endedAt: new Date(), joined: [], endReason } },
    { new: true }
  ).select('members chat group');
  const recipients = new Set([
    ...participants,
    ...(call?.members || []).map(String)
  ]);
  recipients.forEach(id => send(id, {
    t: 'call-ended',
    room,
    chat: call?.chat,
    group: call?.group && String(call.group)
  }));
};
const presence = (id, isOnline) => {
  if (isOnline) active.add(String(id));
  else active.delete(String(id));
  online.forEach((_, recipient) => send(recipient, { t: 'presence', id: String(id), on: isOnline }));
};
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
  const groups = await Group.find().select('_id members');
  for (const group of groups) {
    await Chat.updateOne(
      { key: String(group.id) },
      { $setOnInsert: { key: String(group.id), kind: 'group', group: group.id, members: group.members } },
      { upsert: true }
    );
  }
  const directChats = await Message.aggregate([
    { $match: { group: null, to: { $ne: null } } },
    { $group: { _id: '$chat', senders: { $addToSet: '$from' }, recipients: { $addToSet: '$to' } } }
  ]);
  for (const chat of directChats) {
    await Chat.updateOne(
      { key: chat._id },
      {
        $setOnInsert: {
          key: chat._id,
          kind: 'direct',
          members: [...new Set([...chat.senders, ...chat.recipients].map(String))]
        }
      },
      { upsert: true }
    );
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
  res.json({ token: signToken(user), user: currentUser(user) });
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
  res.json({ token: signToken(user), user: currentUser(user) });
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
  }
  if (theme !== undefined) {
    if (!theme || typeof theme !== 'object' || Array.isArray(theme)) throw httpError(400, 'Invalid theme');
    user.theme = {
      accent: /^#[0-9a-f]{6}$/i.test(theme.accent) ? theme.accent : user.theme.accent,
      wallpaper: ['dark', 'light'].includes(theme.wallpaper) ? theme.wallpaper : user.theme.wallpaper
    };
  }
  await user.save();
  presence(user.id, user.activeStatus && online.has(user.id));
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
  const chats = await Chat.find({ members: req.uid }).sort({ lastMessageAt: -1, updatedAt: -1 }).limit(100);
  const chatKeys = chats.map(chat => chat.key);
  const messageIds = chats.map(chat => chat.lastMessage).filter(Boolean);
  const [latestMessages, unreadRows] = await Promise.all([
    messageIds.length ? Message.find({ _id: { $in: messageIds } }) : [],
    chatKeys.length ? Message.aggregate([
      { $match: { chat: { $in: chatKeys }, from: { $ne: new mongoose.Types.ObjectId(req.uid) }, status: { $ne: 'seen' } } },
      { $group: { _id: '$chat', count: { $sum: 1 } } }
    ]) : []
  ]);
  const messageById = new Map(latestMessages.map(message => [String(message.id), messageResponse(message)]));
  const unreadByChat = new Map(unreadRows.map(row => [row._id, row.count]));
  const peerIds = [...new Set(chats.filter(chat => chat.kind === 'direct')
    .flatMap(chat => chat.members.map(String).filter(id => id !== req.uid)))];
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
      id: chat.group ? String(chat.group) : chat.members.map(String).find(id => id !== req.uid),
      kind: chat.kind,
      members: chat.members.map(String),
      group: chat.group && String(chat.group),
      lastMessageAt: chat.lastMessageAt,
      lastMessage: chat.lastMessage ? messageById.get(String(chat.lastMessage)) || null : null,
      unreadCount: unreadByChat.get(chat.key) || 0
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
  const group = await Group.create({ name, owner: req.uid, members });
  await Chat.create({ key: String(group.id), kind: 'group', group: group.id, members });
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
  const filter = { chat };
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

  const callFilter = {
    chat,
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

app.get('/api/media/:id', auth, asyncRoute(async (req, res) => {
  const id = requireObjectId(req.params.id, 'media id');
  const media = await Media.findOne({ _id: id, access: req.uid });
  if (!media) throw httpError(404, 'Media not found');
  res.type(media.mime).set('Cache-Control', 'private, no-store').send(decrypt(media.ct));
}));

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 64 * 1024 });

wss.on('connection', async (socket, req) => {
  const origin = req.headers.origin;
  if (origin && !origins.includes(origin)) return socket.close(4003, 'Origin not allowed');
  let uid;
  try {
    const token = new URL(req.url, 'http://localhost').searchParams.get('token');
    const payload = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'chatapp',
      audience: 'chatapp-api'
    });
    if (typeof payload === 'string' || typeof payload.id !== 'string' || !mongoose.isValidObjectId(payload.id)) {
      return socket.close(4001, 'Unauthorized');
    }
    uid = payload.id;
  } catch {
    return socket.close(4001, 'Unauthorized');
  }

  try {
    const user = await User.findById(uid);
    if (!user) return socket.close(4001, 'Unauthorized');
    if (!online.has(uid)) online.set(uid, new Set());
    online.get(uid).add(socket);
    if (user.activeStatus) presence(uid, true);
    socket.send(JSON.stringify({ t: 'online', ids: [...active] }));

    const handle = async event => {
      if (!event || typeof event !== 'object' || Array.isArray(event) || typeof event.t !== 'string') {
        throw httpError(400, 'Invalid event');
      }
      switch (event.t) {
        case 'msg': {
          const kind = event.kind || 'text';
          if (!['text', 'image', 'audio'].includes(kind) || typeof event.text !== 'string' || event.text.length > 4000) {
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
                (kind === 'audio' && !media.mime.startsWith('audio/'))) {
              throw httpError(400, 'Invalid media attachment');
            }
            content = mediaId;
            await Media.updateOne({ _id: mediaId }, { $addToSet: { access: { $each: recipients } } });
          }

          await Chat.findOneAndUpdate(
            { key: chat },
            { $setOnInsert: { key: chat, kind: groupId ? 'group' : 'direct', members: recipients, group: groupId } },
            { upsert: true, new: true, runValidators: true }
          );
          let message, inserted = true;
          try {
            message = await Message.create({
              chat,
              from: uid,
              to: groupId ? undefined : recipients.find(recipient => recipient !== uid),
              group: groupId,
              clientId: event.clientId,
              kind,
              ct: encrypt(Buffer.from(content)),
              status: 'sent'
            });
          } catch (error) {
            if (error.code !== 11000 || !event.clientId) throw error;
            message = await Message.findOne({ from: uid, clientId: event.clientId });
            if (!message) throw error;
            inserted = false;
          }
          if (inserted) {
            await Chat.updateOne({ key: chat }, { lastMessage: message.id, lastMessageAt: message.createdAt });
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
            await Message.updateMany({ chat: groupId, from: { $ne: uid }, status: { $ne: 'seen' } }, { status: 'seen' });
            members.forEach(member => send(member, { t: 'seen', by: uid, group: groupId }));
          } else {
            const peerId = requireObjectId(event.chat, 'chat id');
            if (!await Chat.exists({ key: chatKey(uid, peerId), members: { $all: [uid, peerId] } })) {
              throw httpError(403, 'Forbidden');
            }
            await Message.updateMany({ chat: chatKey(uid, peerId), to: uid, status: { $ne: 'seen' } }, { status: 'seen' });
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
            message.edited = true;
          } else {
            if (message.kind !== 'text') {
              const mediaId = decrypt(message.ct).toString();
              if (mongoose.isValidObjectId(mediaId)) await Media.deleteOne({ _id: mediaId, owner: uid });
            }
            message.ct = encrypt(Buffer.alloc(0));
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
          const existingCall = await Call.findOne({ room });
          if (existingCall) throw httpError(409, 'Call room is unavailable');
          const call = await Call.create({
            room,
            chat: callChat,
            group: groupId,
            createdBy: uid,
            members: [...new Set(recipients)],
            joined: [uid],
            video: Boolean(event.video)
          });
          if (!rooms.has(room)) rooms.set(room, new Set([uid]));
          recipients.forEach(id => send(id, { t: 'call-log', room, chat: call.chat, group: groupId }));
          recipients.filter(id => id !== uid).forEach(id => send(id, {
            t: 'call-invite',
            from: uid,
            fromName: user.displayName,
            room,
            video: call.video,
            name: typeof event.name === 'string' ? event.name.slice(0, 80) : undefined
          }));
          break;
        }
        case 'call-join': {
          const room = event.room;
          if (typeof room !== 'string' || room.length > 128) throw httpError(400, 'Invalid call room');
          const call = await Call.findOneAndUpdate(
            { room, members: uid, endedAt: { $exists: false } },
            { $addToSet: { joined: uid } },
            { new: true }
          );
          if (!call) throw httpError(403, 'Call invite required');
          if (String(call.createdBy) !== uid) {
            await Call.updateOne({ _id: call.id }, { $set: { answeredAt: new Date() } });
          }
          const participants = rooms.get(room) || new Set();
          socket.send(JSON.stringify({ t: 'call-peers', room, ids: [...participants].filter(id => id !== uid) }));
          participants.add(uid);
          rooms.set(room, participants);
          participants.forEach(id => {
            if (id !== uid) send(id, { t: 'call-joined', room, id: uid });
          });
          break;
        }
        case 'call-leave': {
          if (typeof event.room !== 'string') throw httpError(400, 'Invalid call room');
          if (rooms.get(event.room)?.has(uid)) await endCall(event.room);
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
          if (typeof room !== 'string' || !rooms.get(room)?.has(uid) || !rooms.get(room)?.has(peerId)) {
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

    socket.on('message', async raw => {
      try {
        await handle(JSON.parse(raw.toString()));
      } catch (error) {
        let clientId;
        try {
          const event = JSON.parse(raw.toString());
          if (typeof event?.clientId === 'string') clientId = event.clientId;
        } catch {}
        socket.send(JSON.stringify({ t: 'error', error: error.status ? error.message : 'Request failed', clientId }));
        if (!error.status) console.error('WebSocket request failed:', error);
      }
    });
    socket.on('close', () => {
      online.get(uid)?.delete(socket);
      if (!online.get(uid)?.size) {
        online.delete(uid);
        for (const [room, participants] of rooms) {
          if (participants.has(uid)) {
            void endCall(room).catch(error => console.error('Call cleanup failed:', error));
          }
        }
        presence(uid, false);
      }
    });
  } catch (error) {
    console.error('WebSocket connection setup failed:', error);
    socket.close(1011, 'Connection setup failed');
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
