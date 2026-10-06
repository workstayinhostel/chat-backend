import mongoose from 'mongoose';

const { Schema, model } = mongoose;
const Id = Schema.Types.ObjectId;

const chatMemberSchema = new Schema({
  user: { type: Id, ref: 'User', required: true },
  lastReadMessageAt: Date,
  unreadCount: { type: Number, default: 0, min: 0 }
}, { _id: false });

export const User = model('User', new Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  googleSub: { type: String, unique: true, sparse: true, select: false },
  emailVerified: { type: Boolean, default: false },
  username: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
  displayName: { type: String, required: true, trim: true, maxlength: 40 },
  passwordHash: { type: String, select: false },
  avatarUrl: { type: String, maxlength: 2048 },
  activeStatus: { type: Boolean, default: true },
  lastSeenAt: Date,
  theme: {
    accent: { type: String, default: '#6366f1' },
    wallpaper: { type: String, enum: ['dark', 'light'], default: 'dark' }
  }
}, { timestamps: true, strict: 'throw' }));

export const Group = model('Group', new Schema({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  description: { type: String, default: '', maxlength: 1000 },
  avatarUrl: { type: String, maxlength: 2048 },
  owner: { type: Id, ref: 'User', required: true },
  admins: [{ type: Id, ref: 'User' }],
  members: [{ type: Id, ref: 'User', required: true }]
}, { timestamps: true, strict: 'throw' }).index({ members: 1, updatedAt: -1 }));

export const Chat = model('Chat', new Schema({
  key: { type: String, required: true, unique: true },
  kind: { type: String, enum: ['direct', 'group'], required: true },
  members: { type: [chatMemberSchema], default: [] },
  group: { type: Id, ref: 'Group' },
  lastMessage: { type: Id, ref: 'Message' },
  lastMessageAt: Date
}, { timestamps: true, strict: 'throw' }).index({ 'members.user': 1, lastMessageAt: -1 }));

export const Message = model('Message', new Schema({
  chat: { type: Id, ref: 'Chat', required: true },
  from: { type: Id, ref: 'User', required: true },
  clientId: String,
  kind: { type: String, enum: ['text', 'image', 'audio', 'video', 'file', 'system'], default: 'text' },
  content: { type: String, default: '' },
  mediaUrl: String,
  readBy: [{ type: Id, ref: 'User' }],
  edited: { type: Boolean, default: false },
  deleted: { type: Boolean, default: false },
  // Retained for compatibility with existing encrypted messages and receipt UI.
  to: { type: Id, ref: 'User' },
  group: { type: Id, ref: 'Group' },
  ct: Buffer,
  status: { type: String, enum: ['sent', 'delivered', 'seen'], default: 'sent' }
}, { timestamps: true, strict: 'throw' })
  .index({ chat: 1, createdAt: -1 })
  .index({ to: 1, status: 1 })
  .index(
    { from: 1, clientId: 1 },
    { unique: true, partialFilterExpression: { clientId: { $type: 'string' } } }
  ));

export const Media = model('Media', new Schema({
  owner: { type: Id, ref: 'User', required: true },
  fileKey: { type: String, unique: true, sparse: true },
  url: String,
  mime: { type: String, required: true },
  size: { type: Number, min: 0 },
  // Retained for the existing authenticated, encrypted /api/upload endpoint.
  access: [{ type: Id, ref: 'User' }],
  ct: Buffer
}, { timestamps: true, strict: 'throw' }).index({ access: 1 }));

export const Call = model('Call', new Schema({
  room: { type: String, required: true, unique: true },
  chat: { type: Id, ref: 'Chat' },
  chatKey: String,
  group: { type: Id, ref: 'Group' },
  createdBy: { type: Id, ref: 'User', required: true },
  members: [{ type: Id, ref: 'User', required: true }],
  joined: [{ type: Id, ref: 'User' }],
  video: { type: Boolean, default: false },
  answeredAt: Date,
  endReason: { type: String, enum: ['ended', 'declined'] },
  endedAt: Date
}, { timestamps: true, strict: 'throw' }));
