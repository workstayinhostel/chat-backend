import { createClient } from '@supabase/supabase-js';

const MAX_IMAGE_BYTES = 500_000;
const BUCKET = 'metufy';
const env = import.meta.env || {};
let storageClient;
let storageClientConfig;

const getStorageClient = ({ supabaseUrl, publishableKey }) => {
  const url = supabaseUrl || env.VITE_SUPABASE_URL;
  const key = publishableKey || env.VITE_SUPABASE_PUBLISHABLE_KEY;
  if (!url || !key) {
    throw new Error('Set VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY before uploading media');
  }
  const clientConfig = `${url}\0${key}`;
  if (!storageClient || storageClientConfig !== clientConfig) {
    storageClient = createClient(url, key, {
      auth: { autoRefreshToken: false, persistSession: false }
    });
    storageClientConfig = clientConfig;
  }
  return storageClient;
};

const canvasBlob = (canvas, mime, quality) => new Promise((resolve, reject) => {
  canvas.toBlob(blob => {
    if (!blob) return reject(new Error('The browser could not encode this image'));
    resolve(blob);
  }, mime, quality);
});

export async function compressImage(file) {
  if (!(file instanceof Blob) || !['image/jpeg', 'image/png', 'image/webp', 'image/avif'].includes(file.type)) {
    throw new TypeError('Expected a JPEG, PNG, WebP, or AVIF image');
  }
  let bitmap;
  let objectUrl;
  try {
    if (typeof createImageBitmap === 'function') {
      bitmap = await createImageBitmap(file);
    } else {
      objectUrl = URL.createObjectURL(file);
      bitmap = await new Promise((resolve, reject) => {
        const image = new Image();
        image.onload = () => resolve(image);
        image.onerror = () => reject(new Error('The selected image could not be decoded'));
        image.src = objectUrl;
      });
    }

    const originalWidth = bitmap.width;
    const originalHeight = bitmap.height;
    if (!originalWidth || !originalHeight) throw new Error('The selected image has invalid dimensions');
    const outputMime = file.type === 'image/jpeg' ? 'image/jpeg' : 'image/webp';
    let scale = Math.min(1, 2560 / Math.max(originalWidth, originalHeight));

    for (let attempt = 0; attempt < 24; attempt += 1) {
      const canvas = document.createElement('canvas');
      canvas.width = Math.max(1, Math.floor(originalWidth * scale));
      canvas.height = Math.max(1, Math.floor(originalHeight * scale));
      const context = canvas.getContext('2d');
      if (!context) throw new Error('Canvas image processing is unavailable');
      context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);

      let low = 0.1;
      let high = 0.98;
      let best;
      const highestQualityBlob = await canvasBlob(canvas, outputMime, high);
      if (highestQualityBlob.size <= MAX_IMAGE_BYTES) return highestQualityBlob;
      const lowestQualityBlob = await canvasBlob(canvas, outputMime, low);
      if (lowestQualityBlob.size <= MAX_IMAGE_BYTES) best = lowestQualityBlob;
      for (let iteration = 0; iteration < 14; iteration += 1) {
        const quality = (low + high) / 2;
        const blob = await canvasBlob(canvas, outputMime, quality);
        if (blob.size <= MAX_IMAGE_BYTES) {
          best = blob;
          low = quality;
        } else {
          high = quality;
        }
      }
      if (best) return best;
      scale *= 0.9;
    }
    throw new RangeError('Could not compress the image to 500,000 bytes or less');
  } finally {
    bitmap?.close?.();
    if (objectUrl) URL.revokeObjectURL(objectUrl);
  }
}

export async function uploadImage(file, options = {}) {
  const folder = options.folder || 'conversations';
  if (!['conversations', 'profiles'].includes(folder)) {
    throw new TypeError('folder must be conversations or profiles');
  }
  const compressed = await compressImage(file);
  if (compressed.size > MAX_IMAGE_BYTES) {
    throw new RangeError('Compressed image must be no larger than 500,000 bytes');
  }

  const apiBaseUrl = options.apiBaseUrl || env.VITE_API_URL || '';
  const request = async (path, body) => {
    const headers = { 'Content-Type': 'application/json' };
    if (options.authToken) headers.Authorization = `Bearer ${options.authToken}`;
    const response = await fetch(`${apiBaseUrl}${path}`, {
      method: 'POST',
      credentials: 'include',
      headers,
      body: JSON.stringify(body)
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `Media request failed (${response.status})`);
    return result;
  };

  const mime = compressed.type || 'image/webp';
  const signedUpload = await request('/api/media/upload-url', {
    folder,
    mime,
    size: compressed.size
  });
  const storage = getStorageClient(options);
  const { error } = await storage.storage.from(BUCKET).uploadToSignedUrl(
    signedUpload.fileKey,
    signedUpload.token,
    compressed,
    { contentType: mime, upsert: false }
  );
  if (error) throw new Error(`Supabase upload failed: ${error.message}`);

  return request('/api/media/complete', {
    folder,
    fileKey: signedUpload.fileKey,
    mime,
    size: compressed.size
  });
}

export const uploadConversationImage = (file, options = {}) =>
  uploadImage(file, { ...options, folder: 'conversations' });

export const uploadProfilePhoto = (file, options = {}) =>
  uploadImage(file, { ...options, folder: 'profiles' });
