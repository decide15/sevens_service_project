#!/bin/bash test

echo "🚀 Pull latest code..."
git pull

echo "📦 Install dependencies..."
npm install

echo "🔄 Restart service..."
pm2 restart sevens_service_project || pm2 start server.js --name sevens_service_project

echo "✅ Deploy done!"