import mongoose from 'mongoose';

const { Schema, model } = mongoose;
const Id = Schema.Types.ObjectId;

export const User = model('User', new Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  googleSub: { type: String, unique: true, sparse: true, select: false },
  emailVerified: { type: Boolean, default: false },
  username: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
  displayName: { type: String, required: true, trim: true, maxlength: 40 },
  passwordHash: { type: String, select: false },
  avatarUrl: { type: String, maxlength: 2048 },
  activeStatus: { type: Boolean, default: true },
  theme: {
    accent: { type: String, default: '#6366f1' },
    wallpaper: { type: String, enum: ['dark', 'light'], default: 'dark' }
  }
}, { timestamps: true, strict: 'throw' }));

export const Group = model('Group', new Schema({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  owner: { type: Id, ref: 'User', required: true },
  members: [{ type: Id, ref: 'User', required: true }]
}, { timestamps: true, strict: 'throw' }).index({ members: 1, updatedAt: -1 }));

export const Chat = model('Chat', new Schema({
  key: { type: String, required: true, unique: true },
  kind: { type: String, enum: ['direct', 'group'], required: true },
  members: [{ type: Id, ref: 'User', required: true }],
  group: { type: Id, ref: 'Group' },
  lastMessage: { type: Id, ref: 'Message' },
  lastMessageAt: Date
}, { timestamps: true, strict: 'throw' }).index({ members: 1, lastMessageAt: -1 }));

export const Message = model('Message', new Schema({
  chat: { type: String, required: true },
  from: { type: Id, ref: 'User', required: true },
  to: { type: Id, ref: 'User' },
  group: { type: Id, ref: 'Group' },
  clientId: String,
  kind: { type: String, enum: ['text', 'image', 'audio'], default: 'text' },
  ct: { type: Buffer, required: true },
  status: { type: String, enum: ['sent', 'delivered', 'seen'], default: 'sent' },
  edited: { type: Boolean, default: false },
  deleted: { type: Boolean, default: false }
}, { timestamps: true, strict: 'throw' })
  .index({ chat: 1, createdAt: -1 })
  .index({ to: 1, status: 1 })
  .index(
    { from: 1, clientId: 1 },
    { unique: true, partialFilterExpression: { clientId: { $type: 'string' } } }
  ));

export const Media = model('Media', new Schema({
  owner: { type: Id, ref: 'User', required: true },
  access: [{ type: Id, ref: 'User' }],
  mime: { type: String, required: true },
  ct: { type: Buffer, required: true }
}, { timestamps: true, strict: 'throw' }).index({ access: 1 }));

export const Call = model('Call', new Schema({
  room: { type: String, required: true, unique: true },
  chat: { type: String, index: true },
  group: { type: Id, ref: 'Group' },
  createdBy: { type: Id, ref: 'User', required: true },
  members: [{ type: Id, ref: 'User', required: true }],
  joined: [{ type: Id, ref: 'User' }],
  video: { type: Boolean, default: false },
  answeredAt: Date,
  endReason: { type: String, enum: ['ended', 'declined'] },
  endedAt: Date
}, { timestamps: true, strict: 'throw' }));
