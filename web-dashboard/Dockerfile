FROM node:18-alpine

# 建立工作目錄
WORKDIR /app

# 複製package檔案
COPY package*.json ./

# 安裝依賴
RUN npm install

# 複製源碼
COPY . .

# 建置應用程式
RUN npm run build

# 暴露埠口
EXPOSE 3000

# 執行命令
CMD ["npm", "start"]
