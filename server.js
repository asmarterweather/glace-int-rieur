// server.js
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://londonjeremie:Narnia2010@cluster0.mtuev.mongodb.net/glace-interieure?retryWrites=true&w=majority';

mongoose.connect(MONGODB_URI)
.then(() => console.log('MongoDB Atlas connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema with authentication
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String }, // hashed
  displayName: { type: String, required: true },
  googleId: { type: String },
  avatar: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Session Schema (simple token-based)
const sessionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  token: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now, expires: 604800 } // 7 days
});

const Session = mongoose.model('Session', sessionSchema);

// Dynamic Module Schema
const moduleSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  description: { type: String, default: '' },
  order: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const Module = mongoose.model('Module', moduleSchema);

// Video Schema (updated for dynamic modules)
const videoSchema = new mongoose.Schema({
  title: { type: String, required: true },
  moduleKey: { type: String, required: true },
  videoUrl: { type: String, required: true },
  thumbnail: { type: String, default: '' },
  duration: { type: String, default: '' },
  description: { type: String, default: '' },
  fileName: { type: String },
  fileSize: { type: Number },
  uploadedAt: { type: Date, default: Date.now }
});

const Video = mongoose.model('Video', videoSchema);

// Post Schema (with user reference)
const postSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  authorName: { type: String, default: 'Anonyme' },
  likes: { type: Number, default: 0 },
  likedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const Post = mongoose.model('Post', postSchema);

// Post Reply Schema (community replies)
const postReplySchema = new mongoose.Schema({
  postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  authorName: { type: String, default: 'Anonyme' },
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const PostReply = mongoose.model('PostReply', postReplySchema);

// Comment Schema
const commentSchema = new mongoose.Schema({
  videoId: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  authorName: { type: String, default: 'Anonyme' },
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Comment = mongoose.model('Comment', commentSchema);

// About Page Schema
const aboutSchema = new mongoose.Schema({
  content: { type: String, default: '' },
  lastUpdated: { type: Date, default: Date.now }
});

const About = mongoose.model('About', aboutSchema);

// Site Settings Schema
const settingsSchema = new mongoose.Schema({
  siteName: { type: String, default: 'Glace Intérieure' },
  tagline: { type: String, default: 'Plateforme de partage et apprentissage' },
  lastUpdated: { type: Date, default: Date.now }
});

// Shorts Schema (TikTok/Reels style short videos)
const shortSchema = new mongoose.Schema({
  title: { type: String, default: '' },
  videoUrl: { type: String, required: true },
  thumbnail: { type: String, default: '' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  authorName: { type: String, default: 'Anonyme' },
  likes: { type: Number, default: 0 },
  likedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  views: { type: Number, default: 0 },
  fileName: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const Short = mongoose.model('Short', shortSchema);

// Marketplace Schema (for selling ice skating equipment)
const marketplaceSchema = new mongoose.Schema({
  title: { type: String, required: true },
  category: { type: String, required: true, enum: ['skates', 'blades', 'accessories', 'other'] },
  description: { type: String, default: '' },
  price: { type: Number, required: true, min: 0 },
  imageUrl: { type: String, default: '' },
  contact: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  authorName: { type: String, default: 'Anonyme' },
  isSold: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const MarketplaceItem = mongoose.model('MarketplaceItem', marketplaceSchema);

// Marketplace Offer Schema (for offers/purchases)
const marketplaceOfferSchema = new mongoose.Schema({
  itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'MarketplaceItem', required: true },
  offerAmount: { type: Number, required: true, min: 0 },
  message: { type: String, default: '' },
  buyerName: { type: String, required: true },
  buyerContact: { type: String, required: true },
  buyerUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: { type: String, enum: ['pending', 'accepted', 'rejected', 'completed'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const MarketplaceOffer = mongoose.model('MarketplaceOffer', marketplaceOfferSchema);

const Settings = mongoose.model('Settings', settingsSchema);

// Password hashing
function hashPassword(password) {
  return crypto.createHash('sha256').update(password + 'glace_salt_2024').digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Auth middleware
async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    req.user = null;
    return next();
  }
  
  try {
    const session = await Session.findOne({ token }).populate('userId');
    if (session && session.userId) {
      req.user = session.userId;
    }
  } catch (error) {
    req.user = null;
  }
  next();
}

app.use(authMiddleware);

// Email Configuration
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '465'),
  secure: process.env.SMTP_SECURE !== 'false', // true for 465, false for 587
  auth: {
    user: process.env.SMTP_USER || 'jejelondon123@gmail.com',
    pass: process.env.SMTP_PASS || 'tztsugaoogyxouoj'
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Verify email connection
transporter.verify(function(error, success) {
  if (error) {
    console.error('Email server connection error:', error);
    console.error('Email configuration:', {
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: process.env.SMTP_PORT || '465',
      user: process.env.SMTP_USER || 'jejelondon123@gmail.com',
      secure: process.env.SMTP_SECURE !== 'false'
    });
  } else {
    console.log('✓ Email server is ready to send messages');
  }
});

// Email sending function
async function sendEmail(to, subject, html, text = '') {
  try {
    const mailOptions = {
      from: `"Glace Intérieure" <${process.env.SMTP_USER || 'jejelondon123@gmail.com'}>`,
      to: to,
      subject: subject,
      html: html,
      text: text || html.replace(/<[^>]*>/g, '')
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent:', info.messageId);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('Email sending error:', error);
    return { success: false, error: error.message };
  }
}

// Email API endpoint
app.post('/api/send-email', async (req, res) => {
  try {
    const { to, subject, html, text } = req.body;

    if (!to || !subject || !html) {
      return res.status(400).json({ error: 'Missing required fields: to, subject, html' });
    }

    const result = await sendEmail(to, subject, html, text);

    if (result.success) {
      res.json({ success: true, message: 'Email sent successfully', messageId: result.messageId });
    } else {
      res.status(500).json({ error: 'Failed to send email', details: result.error });
    }
  } catch (error) {
    console.error('Email API error:', error);
    res.status(500).json({ error: 'Failed to send email: ' + error.message });
  }
});

// Test email endpoint
app.post('/api/test-email', async (req, res) => {
  try {
    const { to } = req.body;
    const testEmail = to || process.env.SMTP_USER || 'jejelondon123@gmail.com';
    
    const result = await sendEmail(
      testEmail,
      'Test Email - Glace Intérieure',
      '<h2>Test Email</h2><p>Ceci est un email de test depuis Glace Intérieure.</p><p>Si vous recevez ce message, la configuration email fonctionne correctement.</p>'
    );

    if (result.success) {
      res.json({ success: true, message: 'Test email sent successfully', messageId: result.messageId });
    } else {
      res.status(500).json({ error: 'Failed to send test email', details: result.error });
    }
  } catch (error) {
    console.error('Test email error:', error);
    res.status(500).json({ error: 'Failed to send test email: ' + error.message });
  }
});

// Backblaze B2 Configuration
const B2_KEY_ID = process.env.B2_KEY_ID || '003df521fad405e0000000001';
const B2_APP_KEY = process.env.B2_APP_KEY || '003df521fad405e0000000001';
const B2_BUCKET_ID = process.env.B2_BUCKET_ID || '8d3f65c281cffa4d94a0051e';
const B2_BUCKET_NAME = process.env.B2_BUCKET_NAME || 'IceSkating';

let b2AuthToken = null;
let b2ApiUrl = null;
let b2DownloadUrl = null;
let uploadUrl = null;
let uploadAuthToken = null;

async function authorizeB2() {
  try {
    const authString = Buffer.from(`${B2_KEY_ID}:${B2_APP_KEY}`).toString('base64');
    const response = await axios.get('https://api.backblazeb2.com/b2api/v2/b2_authorize_account', {
      headers: { 'Authorization': `Basic ${authString}` }
    });
    b2AuthToken = response.data.authorizationToken;
    b2ApiUrl = response.data.apiUrl;
    b2DownloadUrl = response.data.downloadUrl;
    console.log('Backblaze B2 authorized');
    return true;
  } catch (error) {
    console.error('B2 Authorization failed:', error.response?.data || error.message);
    return false;
  }
}

async function getUploadUrl() {
  try {
    const response = await axios.post(
      `${b2ApiUrl}/b2api/v2/b2_get_upload_url`,
      { bucketId: B2_BUCKET_ID },
      { headers: { 'Authorization': b2AuthToken } }
    );
    uploadUrl = response.data.uploadUrl;
    uploadAuthToken = response.data.authorizationToken;
    return true;
  } catch (error) {
    console.error('Failed to get upload URL:', error.response?.data || error.message);
    return false;
  }
}

async function uploadToB2(fileBuffer, fileName, contentType) {
  try {
    if (!uploadUrl || !uploadAuthToken) await getUploadUrl();
    const sha1Hash = crypto.createHash('sha1').update(fileBuffer).digest('hex');
    const response = await axios.post(uploadUrl, fileBuffer, {
      headers: {
        'Authorization': uploadAuthToken,
        'X-Bz-File-Name': encodeURIComponent(fileName),
        'Content-Type': contentType,
        'X-Bz-Content-Sha1': sha1Hash,
        'X-Bz-Info-Author': 'GlaceInterieure'
      }
    });
    return `${b2DownloadUrl}/file/${B2_BUCKET_NAME}/${fileName}`;
  } catch (error) {
    uploadUrl = null;
    uploadAuthToken = null;
    throw error;
  }
}

async function deleteFromB2(fileName) {
  try {
    const listResponse = await axios.post(
      `${b2ApiUrl}/b2api/v2/b2_list_file_names`,
      { bucketId: B2_BUCKET_ID, prefix: fileName, maxFileCount: 1 },
      { headers: { 'Authorization': b2AuthToken } }
    );
    if (listResponse.data.files?.length > 0) {
      await axios.post(
        `${b2ApiUrl}/b2api/v2/b2_delete_file_version`,
        { fileId: listResponse.data.files[0].fileId, fileName },
        { headers: { 'Authorization': b2AuthToken } }
      );
      return true;
    }
  } catch (error) {
    console.error('B2 Delete failed:', error.response?.data || error.message);
    return false;
  }
}

// Initialize default modules
async function initializeDefaultModules() {
  const count = await Module.countDocuments();
  if (count === 0) {
    await Module.insertMany([
      { key: 'corps', name: 'Corps & Glisse', description: 'Techniques de patinage', order: 1 },
      { key: 'esprit', name: 'Esprit & Confiance', description: 'Développement mental', order: 2 },
      { key: 'force', name: 'Force & Mobilité', description: 'Renforcement musculaire', order: 3 }
    ]);
    console.log('Default modules initialized');
  }
}

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'client.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// Admin authentication
app.post('/api/admin/auth', (req, res) => {
  const { password } = req.body;
  const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
  
  if (password === adminPassword) {
    const adminToken = crypto.randomBytes(32).toString('hex');
    res.json({ success: true, token: adminToken });
  } else {
    res.status(401).json({ error: 'Mot de passe incorrect' });
  }
});

// AUTH ROUTES
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, displayName } = req.body;
    if (!email || !password || !displayName) {
      return res.status(400).json({ error: 'All fields required' });
    }
    
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    const user = new User({
      email,
      password: hashPassword(password),
      displayName
    });
    await user.save();
    
    const token = generateToken();
    await new Session({ userId: user._id, token }).save();
    
    res.json({ success: true, user: { id: user._id, email, displayName }, token });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, password: hashPassword(password) });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = generateToken();
    await new Session({ userId: user._id, token }).save();
    
    res.json({ success: true, user: { id: user._id, email: user.email, displayName: user.displayName }, token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) {
    await Session.deleteOne({ token });
  }
  res.json({ success: true });
});

app.get('/api/auth/me', async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  res.json({ user: { _id: req.user._id, id: req.user._id, email: req.user.email, displayName: req.user.displayName } });
});

// MODULES ROUTES
app.get('/api/modules', async (req, res) => {
  try {
    const modules = await Module.find({ isActive: true }).sort({ order: 1 });
    res.json(modules);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch modules' });
  }
});

app.get('/api/modules/all', async (req, res) => {
  try {
    const modules = await Module.find().sort({ order: 1 });
    res.json(modules);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch modules' });
  }
});

app.post('/api/modules', async (req, res) => {
  try {
    const { key, name, description } = req.body;
    if (!key || !name) {
      return res.status(400).json({ error: 'Key and name required' });
    }
    
    const existing = await Module.findOne({ key });
    if (existing) {
      return res.status(400).json({ error: 'Module key already exists' });
    }
    
    const maxOrder = await Module.findOne().sort({ order: -1 });
    const module = new Module({
      key: key.toLowerCase().replace(/\s+/g, '-'),
      name,
      description: description || '',
      order: (maxOrder?.order || 0) + 1
    });
    await module.save();
    
    res.json({ success: true, module });
  } catch (error) {
    console.error('Create module error:', error);
    res.status(500).json({ error: 'Failed to create module' });
  }
});

app.put('/api/modules/:id', async (req, res) => {
  try {
    const { name, description, isActive, order } = req.body;
    const update = {};
    if (name !== undefined) update.name = name;
    if (description !== undefined) update.description = description;
    if (isActive !== undefined) update.isActive = isActive;
    if (order !== undefined) update.order = order;
    
    const module = await Module.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!module) {
      return res.status(404).json({ error: 'Module not found' });
    }
    res.json({ success: true, module });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update module' });
  }
});

app.delete('/api/modules/:id', async (req, res) => {
  try {
    const module = await Module.findById(req.params.id);
    if (!module) {
      return res.status(404).json({ error: 'Module not found' });
    }
    
    // Check if videos exist in this module
    const videoCount = await Video.countDocuments({ moduleKey: module.key });
    if (videoCount > 0) {
      return res.status(400).json({ error: `Cannot delete: ${videoCount} videos in this module` });
    }
    
    await Module.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete module' });
  }
});

// VIDEO ROUTES
app.get('/api/videos', async (req, res) => {
  try {
    const videos = await Video.find().sort({ uploadedAt: -1 });
    res.json(videos);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

app.get('/api/videos/:id', async (req, res) => {
  try {
    const video = await Video.findById(req.params.id);
    if (!video) return res.status(404).json({ error: 'Video not found' });
    res.json(video);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch video' });
  }
});

app.post('/api/videos', upload.single('video'), async (req, res) => {
  try {
    const { title, moduleKey, description } = req.body;
    const videoFile = req.file;
    
    if (!videoFile) return res.status(400).json({ error: 'No video file' });
    if (!b2AuthToken) await authorizeB2();
    
    const timestamp = Date.now();
    const fileName = `videos/${timestamp}-${videoFile.originalname.replace(/\s+/g, '-')}`;
    const videoUrl = await uploadToB2(videoFile.buffer, fileName, videoFile.mimetype);
    
    const newVideo = new Video({
      title,
      moduleKey,
      videoUrl,
      description,
      fileName,
      fileSize: videoFile.size
    });
    await newVideo.save();
    
    res.json({ success: true, video: newVideo });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to upload video' });
  }
});

app.put('/api/videos/:id', async (req, res) => {
  try {
    const { title, moduleKey, description, duration } = req.body;
    const video = await Video.findByIdAndUpdate(
      req.params.id,
      { title, moduleKey, description, duration },
      { new: true }
    );
    if (!video) return res.status(404).json({ error: 'Video not found' });
    res.json({ success: true, video });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update video' });
  }
});

app.delete('/api/videos/:id', async (req, res) => {
  try {
    const video = await Video.findById(req.params.id);
    if (!video) return res.status(404).json({ error: 'Video not found' });
    if (video.fileName) await deleteFromB2(video.fileName);
    await Video.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete video' });
  }
});

// POSTS ROUTES
app.get('/api/posts', async (req, res) => {
  try {
    const posts = await Post.find().sort({ createdAt: -1 });
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

app.post('/api/posts', async (req, res) => {
  try {
    const { title, content } = req.body;
    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content required' });
    }
    
    const newPost = new Post({
      title,
      content,
      userId: req.user?._id,
      authorName: req.user?.displayName || 'Anonyme'
    });
    await newPost.save();
    res.json({ success: true, post: newPost });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create post' });
  }
});

app.get('/api/posts/:id', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });
    res.json(post);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch post' });
  }
});

// Post replies
app.get('/api/posts/:id/replies', async (req, res) => {
  try {
    const replies = await PostReply.find({ postId: req.params.id }).sort({ createdAt: 1 });
    res.json(replies);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch replies' });
  }
});

app.post('/api/posts/:id/replies', async (req, res) => {
  try {
    const { content } = req.body;
    if (!content) {
      return res.status(400).json({ error: 'Content required' });
    }

    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });

    const reply = new PostReply({
      postId: req.params.id,
      userId: req.user?._id,
      authorName: req.user?.displayName || 'Anonyme',
      content
    });
    await reply.save();

    res.json({ success: true, reply });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create reply' });
  }
});

app.post('/api/posts/:id/like', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });
    
    // Check if user already liked
    if (req.user && post.likedBy.includes(req.user._id)) {
      return res.json({ success: true, likes: post.likes });
    }
    
    post.likes += 1;
    if (req.user) post.likedBy.push(req.user._id);
    await post.save();
    
    res.json({ success: true, likes: post.likes });
  } catch (error) {
    res.status(500).json({ error: 'Failed to like post' });
  }
});

app.delete('/api/posts/:id', async (req, res) => {
  try {
    await Post.findByIdAndDelete(req.params.id);
    await PostReply.deleteMany({ postId: req.params.id });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete post' });
  }
});

// COMMENTS ROUTES
app.get('/api/videos/:id/comments', async (req, res) => {
  try {
    const comments = await Comment.find({ videoId: req.params.id }).sort({ createdAt: -1 });
    res.json(comments);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

app.post('/api/videos/:id/comments', async (req, res) => {
  try {
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: 'Content required' });
    
    const newComment = new Comment({
      videoId: req.params.id,
      userId: req.user?._id,
      authorName: req.user?.displayName || 'Anonyme',
      content
    });
    await newComment.save();
    res.json({ success: true, comment: newComment });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create comment' });
  }
});

// SHORTS ROUTES (TikTok/Reels style)
app.get('/api/shorts', async (req, res) => {
  try {
    const shorts = await Short.find().sort({ createdAt: -1 });
    res.json(shorts);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch shorts' });
  }
});

app.post('/api/shorts', upload.single('video'), async (req, res) => {
  try {
    const { title } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ error: 'Video file required' });
    }

    // Upload to B2
    const fileName = `shorts/${Date.now()}_${req.file.originalname}`;
    const videoUrl = await uploadToB2(req.file.buffer, fileName, req.file.mimetype);

    const newShort = new Short({
      title: title || '',
      videoUrl,
      fileName,
      userId: req.user?._id,
      authorName: req.user?.displayName || 'Anonyme'
    });

    await newShort.save();
    res.json({ success: true, short: newShort });
  } catch (error) {
    console.error('Short upload error:', error);
    res.status(500).json({ error: 'Failed to upload short' });
  }
});

app.post('/api/shorts/:id/like', async (req, res) => {
  try {
    const short = await Short.findById(req.params.id);
    if (!short) return res.status(404).json({ error: 'Short not found' });
    
    if (req.user && short.likedBy.includes(req.user._id)) {
      return res.json({ success: true, likes: short.likes });
    }
    
    short.likes += 1;
    if (req.user) short.likedBy.push(req.user._id);
    await short.save();
    
    res.json({ success: true, likes: short.likes });
  } catch (error) {
    res.status(500).json({ error: 'Failed to like short' });
  }
});

app.post('/api/shorts/:id/view', async (req, res) => {
  try {
    await Short.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to record view' });
  }
});

app.delete('/api/shorts/:id', async (req, res) => {
  try {
    const short = await Short.findById(req.params.id);
    if (!short) return res.status(404).json({ error: 'Short not found' });
    
    if (short.fileName) await deleteFromB2(short.fileName);
    await Short.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete short' });
  }
});

// MARKETPLACE ROUTES
app.get('/api/marketplace', async (req, res) => {
  try {
    const { category } = req.query;
    const query = { isSold: false };
    if (category && category !== 'all') {
      query.category = category;
    }
    const items = await MarketplaceItem.find(query).sort({ createdAt: -1 });
    res.json(items);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch marketplace items' });
  }
});

// Get current user's items
app.get('/api/marketplace/my-items', async (req, res) => {
  try {
    console.log('=== My Items GET ===');
    console.log('req.user:', req.user);
    
    if (!req.user || !req.user._id) {
      console.log('No user, returning empty array');
      return res.json([]);
    }
    
    const userId = req.user._id;
    console.log('Looking for items with userId:', userId);
    
    const items = await MarketplaceItem.find({ userId: userId }).sort({ createdAt: -1 });
    console.log('Found items:', items.length);
    
    res.json(items);
  } catch (error) {
    console.error('My items error:', error);
    res.status(500).json({ error: 'Failed to fetch my items' });
  }
});

app.post('/api/marketplace', upload.single('image'), async (req, res) => {
  try {
    console.log('=== Marketplace POST ===');
    console.log('Auth header:', req.headers.authorization);
    console.log('req.user:', req.user);
    console.log('req.user._id:', req.user?._id);
    
    // Only logged in users can sell
    if (!req.user || !req.user._id) {
      console.log('No user found, returning 401');
      return res.status(401).json({ error: 'Vous devez être connecté pour vendre un équipement' });
    }

    const { title, category, description, price, contact } = req.body;
    
    if (!title || !category || !price || !contact) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    let imageUrl = '';
    if (req.file) {
      const fileName = `marketplace/${Date.now()}_${req.file.originalname}`;
      imageUrl = await uploadToB2(req.file.buffer, fileName, req.file.mimetype);
    }

    const userId = req.user._id;
    const authorName = req.user.displayName || 'Anonyme';
    
    console.log('Creating item with userId:', userId, 'authorName:', authorName);

    const newItem = new MarketplaceItem({
      title,
      category,
      description: description || '',
      price: parseFloat(price),
      imageUrl,
      contact,
      userId: userId,
      authorName: authorName
    });

    await newItem.save();
    console.log('Item saved:', newItem._id, 'with userId:', newItem.userId);
    res.json({ success: true, item: newItem });
  } catch (error) {
    console.error('Marketplace error:', error);
    res.status(500).json({ error: 'Failed to create marketplace item' });
  }
});

app.put('/api/marketplace/:id/sold', async (req, res) => {
  try {
    const item = await MarketplaceItem.findByIdAndUpdate(
      req.params.id,
      { isSold: true },
      { new: true }
    );
    if (!item) return res.status(404).json({ error: 'Item not found' });
    res.json({ success: true, item });
  } catch (error) {
    res.status(500).json({ error: 'Failed to mark item as sold' });
  }
});

app.delete('/api/marketplace/:id', async (req, res) => {
  try {
    const item = await MarketplaceItem.findById(req.params.id);
    if (!item) return res.status(404).json({ error: 'Item not found' });
    
    if (item.imageUrl) {
      const fileName = item.imageUrl.split('/').pop();
      await deleteFromB2(`marketplace/${fileName}`);
    }
    await MarketplaceItem.findByIdAndDelete(req.params.id);
    await MarketplaceOffer.deleteMany({ itemId: req.params.id });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete item' });
  }
});

// Marketplace Offers Routes
app.get('/api/marketplace/:id/offers', async (req, res) => {
  try {
    const offers = await MarketplaceOffer.find({ itemId: req.params.id }).sort({ createdAt: -1 });
    res.json(offers);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch offers' });
  }
});

app.post('/api/marketplace/:id/offers', async (req, res) => {
  try {
    // Only logged in users can make offers
    if (!req.user) {
      return res.status(401).json({ error: 'Vous devez être connecté pour faire une offre' });
    }

    const { offerAmount, message, buyerContact } = req.body;
    const item = await MarketplaceItem.findById(req.params.id);
    if (!item) return res.status(404).json({ error: 'Item not found' });
    if (item.isSold) return res.status(400).json({ error: 'Item already sold' });

    // Prevent users from making offers on their own items
    if (item.userId) {
      const itemOwnerId = String(item.userId);
      const currentUserId = String(req.user._id);
      
      if (itemOwnerId === currentUserId) {
        return res.status(400).json({ error: 'Vous ne pouvez pas faire une offre sur votre propre équipement' });
      }
    }

    if (!offerAmount || offerAmount <= 0) {
      return res.status(400).json({ error: 'Valid offer amount required' });
    }

    const newOffer = new MarketplaceOffer({
      itemId: req.params.id,
      offerAmount: parseFloat(offerAmount),
      message: message || '',
      buyerName: req.user?.displayName || 'Anonyme',
      buyerContact: buyerContact || req.user?.email || '',
      buyerUserId: req.user?._id,
      status: 'pending'
    });

    await newOffer.save();
    
    // Send email notification to seller
    try {
      const sellerEmail = item.contact; // Use contact from item
      if (sellerEmail && sellerEmail.includes('@')) {
        const emailSubject = `Nouvelle offre reçue pour "${item.title}"`;
        const emailHtml = `
          <h2>Nouvelle offre reçue</h2>
          <p>Vous avez reçu une nouvelle offre pour votre équipement "<strong>${item.title}</strong>".</p>
          <p><strong>Montant de l'offre:</strong> ${parseFloat(offerAmount).toFixed(2)} €</p>
          <p><strong>Prix demandé:</strong> ${parseFloat(item.price).toFixed(2)} €</p>
          <p><strong>Offreur:</strong> ${req.user?.displayName || 'Anonyme'}</p>
          ${message ? `<p><strong>Message:</strong> ${message}</p>` : ''}
          <p><strong>Contact de l'offreur:</strong> ${buyerContact || req.user?.email || 'Non fourni'}</p>
          <p>Connectez-vous à votre compte pour voir et gérer cette offre.</p>
        `;
        await sendEmail(sellerEmail, emailSubject, emailHtml);
        console.log('Offer notification email sent to seller');
      }
    } catch (emailError) {
      console.error('Failed to send offer notification email:', emailError);
      // Don't fail the offer creation if email fails
    }
    
    res.json({ success: true, offer: newOffer });
  } catch (error) {
    console.error('Offer error:', error);
    res.status(500).json({ error: 'Failed to create offer: ' + error.message });
  }
});

app.put('/api/marketplace/offers/:id/accept', async (req, res) => {
  try {
    // Only logged in users can accept offers
    if (!req.user) {
      return res.status(401).json({ error: 'Vous devez être connecté pour accepter une offre' });
    }

    const offer = await MarketplaceOffer.findById(req.params.id);
    if (!offer) return res.status(404).json({ error: 'Offer not found' });

    const item = await MarketplaceItem.findById(offer.itemId);
    if (!item) return res.status(404).json({ error: 'Item not found' });

    // Only the item owner can accept offers
    if (!item.userId) {
      return res.status(403).json({ error: 'Cet équipement n\'a pas de propriétaire enregistré' });
    }
    
    // Compare ObjectIds - handle both ObjectId objects and strings
    const itemOwnerId = String(item.userId);
    const currentUserId = String(req.user._id);
    
    if (itemOwnerId !== currentUserId) {
      return res.status(403).json({ error: 'Seul le propriétaire de l\'équipement peut accepter une offre' });
    }

    // Prevent accepting own offers (buyer cannot be the same as seller)
    if (offer.buyerUserId) {
      const buyerId = String(offer.buyerUserId);
      if (buyerId === currentUserId) {
        return res.status(400).json({ error: 'Vous ne pouvez pas accepter votre propre offre' });
      }
    }

    // Mark offer as accepted and item as sold
    offer.status = 'accepted';
    await offer.save();

    item.isSold = true;
    await item.save();

    // Reject other pending offers
    await MarketplaceOffer.updateMany(
      { itemId: offer.itemId, _id: { $ne: req.params.id }, status: 'pending' },
      { status: 'rejected' }
    );

    res.json({ success: true, offer, item });
  } catch (error) {
    res.status(500).json({ error: 'Failed to accept offer' });
  }
});

app.put('/api/marketplace/offers/:id/reject', async (req, res) => {
  try {
    const offer = await MarketplaceOffer.findByIdAndUpdate(
      req.params.id,
      { status: 'rejected' },
      { new: true }
    );
    if (!offer) return res.status(404).json({ error: 'Offer not found' });
    res.json({ success: true, offer });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reject offer' });
  }
});

// ABOUT & SETTINGS ROUTES
app.get('/api/about', async (req, res) => {
  try {
    let about = await About.findOne();
    if (!about) {
      about = new About({ content: 'Bienvenue sur Glace Intérieure.' });
      await about.save();
    }
    res.json(about);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch about' });
  }
});

app.put('/api/about', async (req, res) => {
  try {
    const { content } = req.body;
    let about = await About.findOne();
    if (!about) about = new About({ content });
    else { about.content = content; about.lastUpdated = new Date(); }
    await about.save();
    res.json({ success: true, about });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update about' });
  }
});

app.get('/api/settings', async (req, res) => {
  try {
    let settings = await Settings.findOne();
    if (!settings) {
      settings = new Settings();
      await settings.save();
    }
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

app.put('/api/settings', async (req, res) => {
  try {
    const { siteName, tagline } = req.body;
    let settings = await Settings.findOne();
    if (!settings) settings = new Settings();
    if (siteName) settings.siteName = siteName;
    if (tagline) settings.tagline = tagline;
    settings.lastUpdated = new Date();
    await settings.save();
    res.json({ success: true, settings });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// Health check
app.get('/api/health', async (req, res) => {
  res.json({
    status: 'ok',
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    backblaze: b2AuthToken ? 'authorized' : 'not authorized'
  });
});

// Initialize and start
Promise.all([authorizeB2(), initializeDefaultModules()]).then(() => {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`
====================================
  Glace Intérieure Platform
====================================
  Client: http://localhost:${PORT}
  Admin:  http://localhost:${PORT}/admin
  Health: http://localhost:${PORT}/api/health
====================================
    `);
  });
});

process.on('SIGINT', async () => {
  console.log('\nShutting down...');
  await mongoose.connection.close();
  process.exit(0);
});
