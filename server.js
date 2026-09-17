import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

dotenv.config();
const app = express(), PORT = process.env.PORT || 5000, secret = process.env.JWT_SECRET || 'development-only-secret';
app.use(cors({ origin: process.env.FRONTEND_URL?.split(',') || true }));
app.use(express.json({ limit: '12mb' }));
app.use(express.static('public'));

const base = {
  ownerId: { type: mongoose.Schema.Types.ObjectId, index: true },
  deletedAt: Date,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
};

const User = mongoose.model('User', new mongoose.Schema({
  ...base,
  name: { type: String, required: true, trim: true },
  email: { type: String, unique: true, required: true, lowercase: true, trim: true },
  phone: String,
  region: String, // optional: shown publicly on the buyers directory
  password: { type: String, required: true, select: false },
  role: { type: String, enum: ['farmer', 'fpo', 'buyer', 'admin'], required: true },
  approvalStatus: { type: String, enum: ['pending', 'approved', 'rejected', 'suspended'], default: 'pending' }
}));

const Lot = mongoose.model('Lot', new mongoose.Schema({
  ...base,
  crop: { type: String, required: true }, variety: String, grade: String,
  quantity: { type: Number, required: true }, expectedPrice: Number, region: String,
  harvestDate: Date, description: String, photos: [String], status: { type: String, default: 'Open' }
}));

const Offer = mongoose.model('Offer', new mongoose.Schema({
  ...base,
  lotId: { type: mongoose.Schema.Types.ObjectId, required: true }, buyerId: mongoose.Schema.Types.ObjectId,
  price: { type: Number, required: true }, quantity: Number,
  status: { type: String, enum: ['Pending', 'Accepted', 'Rejected', 'Withdrawn'], default: 'Pending' }
}));

const Order = mongoose.model('Order', new mongoose.Schema({
  ...base,
  lotId: mongoose.Schema.Types.ObjectId, offerId: mongoose.Schema.Types.ObjectId,
  farmerId: mongoose.Schema.Types.ObjectId, buyerId: mongoose.Schema.Types.ObjectId,
  status: { type: String, enum: ['Pending', 'Confirmed', 'Shipped', 'Out for Delivery', 'Delivered', 'Cancelled'], default: 'Pending' },
  paymentStatus: { type: String, enum: ['Pending', 'Paid', 'Failed', 'Refunded'], default: 'Pending' },
  transport: String
}));

// Equipment is its own model — kept out of the generic `resource` loop below
// because only admins are allowed to create/edit/remove tool listings
// (farmers and FPOs may only browse them).
const Equipment = mongoose.model('Equipment', new mongoose.Schema({
  ...base,
  name: { type: String, required: true }, type: String, price: Number, location: String,
  availability: String, ownerType: String, photos: [String]
}));

const Generic = {
  Scheme: mongoose.model('Scheme', new mongoose.Schema({ ...base, title: { type: String, required: true }, description: String, url: String, active: { type: Boolean, default: true } })),
  Grievance: mongoose.model('Grievance', new mongoose.Schema({ ...base, subject: { type: String, required: true }, description: String, status: { type: String, default: 'Open' } })),
  Notification: mongoose.model('Notification', new mongoose.Schema({ ...base, userId: mongoose.Schema.Types.ObjectId, message: String, channel: { type: String, default: 'sms-log' }, status: { type: String, default: 'logged' } })),
  Requirement: mongoose.model('Requirement', new mongoose.Schema({ ...base, crop: String, quantity: Number, region: String, price: Number, status: { type: String, default: 'Open' } })),
  MarketPrice: mongoose.model('MarketPrice', new mongoose.Schema({ ...base, crop: String, region: String, price: Number, source: { type: String, default: 'demo' }, updatedAt: { type: Date, default: Date.now } })),
  Equipment
};

const auth = (req, res, next) => { try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), secret); next() } catch { res.status(401).json({ error: 'Authentication required' }) } };
const allow = (...roles) => (req, res, next) => roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Permission denied' });
const admin = allow('admin');
const clean = u => { let o = u.toObject ? u.toObject() : u; delete o.password; return o };
const changed = (m, id, data) => m.findByIdAndUpdate(id, { $set: { ...data, updatedAt: new Date() } }, { new: true });

app.get('/api/health', (q, s) => s.json({ ok: true, name: 'AgriLink API', database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' }));

app.post('/api/auth/register', async (req, res) => {
  try {
    let { name, email, password, phone = '', region = '', role } = req.body;
    if (!name || !email || !password || password.length < 6 || !['farmer', 'fpo', 'buyer'].includes(role))
      return res.status(400).json({ error: 'Name, valid role, email and a 6+ character password are required' });
    let u = await User.create({ name, email, phone, region, password: await bcrypt.hash(password, 12), role });
    res.status(201).json({ message: 'Registration submitted for admin approval', user: clean(u) })
  } catch (e) { res.status(e.code === 11000 ? 409 : 400).json({ error: e.code === 11000 ? 'Email already registered' : 'Registration failed' }) }
});
app.post('/api/auth/login', async (req, res) => {
  let u = await User.findOne({ email: String(req.body.email || '').toLowerCase() }).select('+password');
  if (!u || !(await bcrypt.compare(req.body.password || '', u.password))) return res.status(401).json({ error: 'Invalid email or password' });
  if (u.role !== 'admin' && u.approvalStatus !== 'approved') return res.status(403).json({ error: `Account is ${u.approvalStatus}` });
  res.json({ token: jwt.sign({ id: u._id, role: u.role }, secret, { expiresIn: '7d' }), user: clean(u) })
});
app.get('/api/me', auth, async (q, s) => s.json(clean(await User.findById(q.user.id))));

// Public directory of approved buyers — no auth required, only safe fields returned.
app.get('/api/buyers', async (q, s) => {
  let buyers = await User.find({ role: 'buyer', approvalStatus: 'approved', deletedAt: null }).select('name region createdAt');
  s.json(buyers.map(clean))
});

app.get('/api/lots', async (q, s) => s.json(await Lot.find({ deletedAt: null }).sort({ createdAt: -1 })));
app.post('/api/lots', auth, allow('farmer', 'fpo'), async (q, s) => s.status(201).json(await Lot.create({ ...q.body, ownerId: q.user.id })));
app.patch('/api/lots/:id', auth, async (q, s) => s.json(await changed(Lot, q.params.id, q.body)));
app.delete('/api/lots/:id', auth, admin, async (q, s) => { let l = await changed(Lot, q.params.id, { deletedAt: new Date() }); l ? s.json({ message: 'Removed' }) : s.status(404).json({ error: 'Lot not found' }) });

app.get('/api/offers', auth, async (q, s) => s.json(await Offer.find(q.user.role === 'buyer' ? { buyerId: q.user.id, deletedAt: null } : { deletedAt: null }).sort({ createdAt: -1 })));
app.post('/api/offers', auth, allow('buyer'), async (q, s) => s.status(201).json(await Offer.create({ ...q.body, buyerId: q.user.id, ownerId: q.user.id })));
app.patch('/api/offers/:id', auth, async (q, s) => {
  let offer = await changed(Offer, q.params.id, q.body);
  if (q.body.status === 'Accepted') {
    let lot = await Lot.findById(offer.lotId);
    await Order.create({ lotId: offer.lotId, offerId: offer._id, farmerId: lot?.ownerId, buyerId: offer.buyerId, status: 'Pending', paymentStatus: 'Pending' });
    await Generic.Notification.create({ userId: offer.buyerId, message: `Your offer for ${lot?.crop || 'a crop lot'} was accepted. Your order is now Pending.`, channel: 'sms-log', status: 'logged' })
  }
  s.json(offer)
});

app.get('/api/orders', auth, async (q, s) => s.json(await Order.find(q.user.role === 'admin' ? { deletedAt: null } : { $or: [{ farmerId: q.user.id }, { buyerId: q.user.id }], deletedAt: null }).sort({ createdAt: -1 })));
app.patch('/api/orders/:id', auth, async (q, s) => {
  let order = await Order.findById(q.params.id);
  if (!order) return s.status(404).json({ error: 'Order not found' });
  if (q.user.role !== 'admin' && String(order.farmerId) !== q.user.id) return s.status(403).json({ error: 'Only the seller or an admin can update this order' });
  let prevStatus = order.status, updated = await changed(Order, q.params.id, q.body);
  if (q.body.status && q.body.status !== prevStatus) {
    let lot = await Lot.findById(order.lotId);
    await Generic.Notification.create({ userId: order.buyerId, message: `Your order for ${lot?.crop || 'your crop lot'} is now "${q.body.status}".`, channel: 'sms-log', status: 'logged' })
  }
  s.json(updated)
});

// Equipment / tool rental — read is open to any signed-in user (farmers and
// FPOs browse), but only admins may create, edit, or remove listings: this
// is the service AgriLink itself provides, not something farmers list.
app.get('/api/equipment', auth, async (q, s) => s.json(await Equipment.find({ deletedAt: null }).sort({ createdAt: -1 })));
app.get('/api/equipment/public', async (q, s) => s.json(await Equipment.find({ deletedAt: null }).sort({ createdAt: -1 })));
app.post('/api/equipment', auth, admin, async (q, s) => s.status(201).json(await Equipment.create({ ...q.body, ownerId: q.user.id })));
app.patch('/api/equipment/:id', auth, admin, async (q, s) => s.json(await changed(Equipment, q.params.id, q.body)));
app.delete('/api/equipment/:id', auth, admin, async (q, s) => { let e = await changed(Equipment, q.params.id, { deletedAt: new Date() }); e ? s.json({ message: 'Removed' }) : s.status(404).json({ error: 'Equipment not found' }) });

const resource = { schemes: Generic.Scheme, grievances: Generic.Grievance, requirements: Generic.Requirement, 'market-prices': Generic.MarketPrice, payments: Order };
for (const [path, Model] of Object.entries(resource)) {
  app.get('/api/' + path, auth, async (q, s) => s.json(await Model.find({ deletedAt: null }).sort({ createdAt: -1 })));
  app.post('/api/' + path, auth, async (q, s) => s.status(201).json(await Model.create({ ...q.body, ownerId: q.user.id })));
  app.patch('/api/' + path + '/:id', auth, async (q, s) => s.json(await changed(Model, q.params.id, q.body)))
}

app.get('/api/notifications', auth, async (q, s) => s.json(await Generic.Notification.find({ ...(q.user.role === 'admin' ? {} : { userId: q.user.id }), deletedAt: null }).sort({ createdAt: -1 })));
app.post('/api/notifications', auth, admin, async (q, s) => s.status(201).json(await Generic.Notification.create({ ...q.body, ownerId: q.user.id })));
app.patch('/api/notifications/:id', auth, async (q, s) => s.json(await changed(Generic.Notification, q.params.id, q.body)));

app.get('/api/admin/users', auth, admin, async (q, s) => s.json((await User.find({ ...q.query, deletedAt: null }).select('+password')).map(clean)));
app.patch('/api/admin/users/:id/status', auth, admin, async (q, s) => { let u = await changed(User, q.params.id, { approvalStatus: q.body.approvalStatus }); u ? s.json(clean(u)) : s.status(404).json({ error: 'User not found' }) });
app.patch('/api/admin/users/bulk/status', auth, admin, async (q, s) => {
  let ids = q.body.ids || [];
  if (!ids.length) return s.status(400).json({ error: 'Select at least one account' });
  await User.updateMany({ _id: { $in: ids } }, { $set: { approvalStatus: q.body.approvalStatus } });
  s.json({ message: 'Accounts updated' })
});
// Soft-delete a single account or a bulk-selected set (checkbox "select all" + delete on the admin Farmers/FPOs/Buyers pages).
app.delete('/api/admin/users/:id', auth, admin, async (q, s) => { let u = await changed(User, q.params.id, { deletedAt: new Date() }); u ? s.json({ message: 'Account deleted' }) : s.status(404).json({ error: 'User not found' }) });
app.delete('/api/admin/users/bulk', auth, admin, async (q, s) => {
  let ids = q.body.ids || [];
  if (!ids.length) return s.status(400).json({ error: 'Select at least one account' });
  await User.updateMany({ _id: { $in: ids } }, { $set: { deletedAt: new Date() } });
  s.json({ message: 'Accounts deleted' })
});
app.get('/api/admin/recycle', auth, admin, async (q, s) => {
  let all = await Promise.all([User, Lot, Offer, Order, ...Object.values(Generic)].map(async M => (await M.find({ deletedAt: { $ne: null } })).map(x => ({ type: M.modelName, ...clean(x) }))));
  s.json(all.flat())
});

app.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => { console.error(err); res.status(400).json({ error: err.message || 'Request failed' }) });

async function seedAdmin() {
  if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) return;
  let email = process.env.ADMIN_EMAIL.toLowerCase();
  await User.findOneAndUpdate({ email }, { $set: { name: 'Administrator', email, password: await bcrypt.hash(process.env.ADMIN_PASSWORD, 12), role: 'admin', approvalStatus: 'approved' } }, { upsert: true, new: true, setDefaultsOnInsert: true })
}
mongoose.connect(process.env.MONGODB_URI).then(async () => { await seedAdmin(); app.listen(PORT, () => console.log('AgriLink API running on ' + PORT)) }).catch(e => { console.error('MongoDB connection failed:', e.message); process.exit(1) });
