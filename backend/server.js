const express = require('express');
const multer = require('multer');
const cors = require('cors');
const crypto = require('crypto');
const { PDFDocument } = require('pdf-lib');
const mongoose = require('mongoose');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/signed-pdfs', express.static('signed-pdfs'));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/pdf-signature-db';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// MongoDB Schema for Audit Trail
const PDFAuditSchema = new mongoose.Schema({
  pdfId: { type: String, required: true },
  originalHash: { type: String, required: true },
  signedHash: { type: String },
  timestamp: { type: Date, default: Date.now },
  coordinates: {
    x: Number,
    y: Number,
    width: Number,
    height: Number
  },
  status: { type: String, enum: ['pending', 'signed'], default: 'pending' }
});

const PDFAudit = mongoose.model('PDFAudit', PDFAuditSchema);

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Helper function to calculate SHA-256 hash
function calculateHash(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

// Helper function to convert base64 to buffer
function base64ToBuffer(base64String) {
  const base64Data = base64String.replace(/^data:image\/\w+;base64,/, '');
  return Buffer.from(base64Data, 'base64');
}

// Endpoint to upload and register a PDF
app.post('/api/upload-pdf', upload.single('pdf'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No PDF file provided' });
    }

    const pdfBuffer = req.file.buffer;
    const pdfId = crypto.randomBytes(16).toString('hex');
    const originalHash = calculateHash(pdfBuffer);

    // Save original PDF
    const uploadDir = path.join(__dirname, 'uploads');
    await fs.mkdir(uploadDir, { recursive: true });
    await fs.writeFile(path.join(uploadDir, `${pdfId}.pdf`), pdfBuffer);

    // Create audit record
    const audit = new PDFAudit({
      pdfId,
      originalHash,
      status: 'pending'
    });
    await audit.save();

    res.json({
      success: true,
      pdfId,
      originalHash,
      message: 'PDF uploaded successfully'
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to upload PDF' });
  }
});

// Main endpoint: Sign PDF
app.post('/api/sign-pdf', async (req, res) => {
  try {
    const { pdfId, signatureImage, coordinates } = req.body;

    // Validation
    if (!pdfId || !signatureImage || !coordinates) {
      return res.status(400).json({ 
        error: 'Missing required fields: pdfId, signatureImage, coordinates' 
      });
    }

    // Find audit record
    const audit = await PDFAudit.findOne({ pdfId });
    if (!audit) {
      return res.status(404).json({ error: 'PDF not found' });
    }

    // Load original PDF
    const pdfPath = path.join(__dirname, 'uploads', `${pdfId}.pdf`);
    const pdfBytes = await fs.readFile(pdfPath);
    const pdfDoc = await PDFDocument.load(pdfBytes);

    // Convert signature image from base64
    const signatureBuffer = base64ToBuffer(signatureImage);
    let signatureImageEmbed;

    // Detect image type and embed
    if (signatureImage.includes('image/png')) {
      signatureImageEmbed = await pdfDoc.embedPng(signatureBuffer);
    } else if (signatureImage.includes('image/jpeg') || signatureImage.includes('image/jpg')) {
      signatureImageEmbed = await pdfDoc.embedJpg(signatureBuffer);
    } else {
      signatureImageEmbed = await pdfDoc.embedPng(signatureBuffer);
    }

    // Get first page
    const pages = pdfDoc.getPages();
    const firstPage = pages[0];

    // CRITICAL COORDINATE CALCULATION
    const { x, y, width, height } = coordinates;

    // Calculate aspect ratio preservation
    const signatureAspectRatio = signatureImageEmbed.width / signatureImageEmbed.height;
    const boxAspectRatio = width / height;

    let drawWidth, drawHeight, drawX, drawY;

    if (signatureAspectRatio > boxAspectRatio) {
      // Signature is wider - fit to width
      drawWidth = width;
      drawHeight = width / signatureAspectRatio;
      drawX = x;
      drawY = y + (height - drawHeight) / 2;
    } else {
      // Signature is taller - fit to height
      drawHeight = height;
      drawWidth = height * signatureAspectRatio;
      drawX = x + (width - drawWidth) / 2;
      drawY = y;
    }

    // Draw signature on PDF
    firstPage.drawImage(signatureImageEmbed, {
      x: drawX,
      y: drawY,
      width: drawWidth,
      height: drawHeight
    });

    // Save signed PDF
    const signedPdfBytes = await pdfDoc.save();
    const signedHash = calculateHash(Buffer.from(signedPdfBytes));

    // Create signed-pdfs directory
    const signedDir = path.join(__dirname, 'signed-pdfs');
    await fs.mkdir(signedDir, { recursive: true });

    const signedFileName = `${pdfId}-signed.pdf`;
    const signedFilePath = path.join(signedDir, signedFileName);
    await fs.writeFile(signedFilePath, signedPdfBytes);

    // Update audit record
    audit.signedHash = signedHash;
    audit.coordinates = coordinates;
    audit.status = 'signed';
    await audit.save();

    // Generate download URL
    const downloadUrl = `${req.protocol}://${req.get('host')}/signed-pdfs/${signedFileName}`;

    res.json({
      success: true,
      message: 'PDF signed successfully',
      downloadUrl,
      auditTrail: {
        pdfId,
        originalHash: audit.originalHash,
        signedHash,
        timestamp: audit.timestamp,
        coordinates
      }
    });

  } catch (error) {
    console.error('Signing error:', error);
    res.status(500).json({ 
      error: 'Failed to sign PDF',
      details: error.message 
    });
  }
});

// Get audit trail for a PDF
app.get('/api/audit/:pdfId', async (req, res) => {
  try {
    const { pdfId } = req.params;
    const audit = await PDFAudit.findOne({ pdfId });

    if (!audit) {
      return res.status(404).json({ error: 'Audit record not found' });
    }

    res.json({
      success: true,
      audit: {
        pdfId: audit.pdfId,
        originalHash: audit.originalHash,
        signedHash: audit.signedHash,
        timestamp: audit.timestamp,
        coordinates: audit.coordinates,
        status: audit.status
      }
    });
  } catch (error) {
    console.error('Audit retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve audit trail' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'Server is running', timestamp: new Date() });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📝 Upload endpoint: http://localhost:${PORT}/api/upload-pdf`);
  console.log(`✍️  Sign endpoint: http://localhost:${PORT}/api/sign-pdf`);
});