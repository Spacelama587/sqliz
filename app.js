const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 3019;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());


const SECRET_KEY = 'my-secret-key';

// Database Connection
const sequelize = new Sequelize('sail_blog', 'root', 'aaaa1234', {
  host: 'sailing-blog.c3eoklznnnhl.ap-south-1.rds.amazonaws.com',
  dialect: 'mysql',
  logging: false 
});

sequelize.authenticate()
  .then(() => console.log('Database connected successfully.'))
  .catch((error) => console.error('Database connection failed:', error));

// Auth Middleware
const authenticateToken = async (req, res, next) => {
  const { token } = req.cookies;

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = await User.findByPk(decoded.id);
    if (!req.user) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Models
const User = sequelize.define('User', {
  nickname: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: false,
    validate: {
      isAlphanumeric: true,
      len: [3],
    },
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [4],
    },
  },
});

const Post = sequelize.define('Post', {
  title: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  content: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
});

User.hasMany(Post, { foreignKey: 'userId' });
Post.belongsTo(User, { foreignKey: 'userId' });

(async () => {
  await sequelize.sync({ force: true });
})();

// Signup API
app.post('/signup', async (req, res) => {
  const { nickname, password, passwordConfirmation } = req.body;

  // Validate nickname format
  if (!/^[a-zA-Z0-9]{3,}$/.test(nickname)) {
    return res.status(400).json({ error: 'Nickname must be alphanumeric and at least 3 characters long.' });
  }

  // Validate password
  if (password !== passwordConfirmation) {
    return res.status(400).json({ error: 'Passwords do not match.' });
  }

  if (password.length < 4 || password.includes(nickname)) {
    return res.status(400).json({ error: 'Password must be at least 4 characters and not contain the nickname.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ nickname, password: hashedPassword });
    res.status(201).json({ message: 'Signup successful!' });
  } catch (error) {
    if (error.name === 'SequelizeUniqueConstraintError') {
      res.status(400).json({ error: 'Duplicate nickname.' });
    } else {
      res.status(500).json({ error: 'Server error.' });
    }
  }
});

// Login API
app.post('/login', async (req, res) => {
  const { nickname, password } = req.body;

  try {
    const user = await User.findOne({ where: { nickname } });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: 'Please verify your nickname or password.' });
    }

    const token = jwt.sign(
      { id: user.id, nickname: user.nickname }, 
      SECRET_KEY, 
      { expiresIn: '1h' }
    );

    res.cookie('token', token, { 
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
      sameSite: 'strict'
    });
    res.status(200).json({ message: 'Login successful.' });
  } catch (error) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// Get all posts API
app.get('/posts', async (req, res) => {
  try {
    const posts = await Post.findAll({
      attributes: ['id', 'title', 'createdAt'],
      include: [{ 
        model: User, 
        attributes: ['nickname'] 
      }],
      order: [['createdAt', 'DESC']],
    });

    res.status(200).json(posts);
  } catch (error) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// Create post API
app.post('/posts', authenticateToken, async (req, res) => {
  const { title, content } = req.body;

  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content are required.' });
  }

  try {
    const post = await Post.create({ 
      title, 
      content, 
      userId: req.user.id 
    });
    
    res.status(201).json({ 
      message: 'Post created successfully.',
      post: {
        id: post.id,
        title: post.title,
        content: post.content,
        createdAt: post.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// Get single post API
app.get('/posts/:id', async (req, res) => {
  try {
    const post = await Post.findOne({
      where: { id: req.params.id },
      attributes: ['id', 'title', 'content', 'createdAt'],
      include: [{ 
        model: User, 
        attributes: ['nickname'] 
      }],
    });

    if (!post) {
      return res.status(404).json({ error: 'Post not found.' });
    }

    res.status(200).json(post);
  } catch (error) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// Update post API
app.put('/posts/:id', authenticateToken, async (req, res) => {
  const { title, content } = req.body;

  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content are required.' });
  }

  try {
    const post = await Post.findOne({ 
      where: { 
        id: req.params.id, 
        userId: req.user.id 
      } 
    });

    if (!post) {
      return res.status(403).json({ error: 'You can only edit your own posts.' });
    }

    post.title = title;
    post.content = content;
    await post.save();

    res.status(200).json({ 
      message: 'Post updated successfully.',
      post: {
        id: post.id,
        title: post.title,
        content: post.content,
        createdAt: post.createdAt,
        updatedAt: post.updatedAt
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// Delete post API
app.delete('/posts/:id', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findOne({ 
      where: { 
        id: req.params.id, 
        userId: req.user.id 
      } 
    });

    if (!post) {
      return res.status(403).json({ error: 'You can only delete your own posts.' });
    }

    await post.destroy();
    res.status(200).json({ message: 'Post deleted successfully.' });
  } catch (error) {
    res.status(500).json({ error: 'Server error.' });
  }
});



// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});