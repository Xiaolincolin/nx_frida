# Frida 脚本开发环境项目模板

## 如何使用

### 1. 安装环境

1. 下载仓库到项目目录, 并解压缩

2. 安装 **node** 和 **npm** 环境 ==( 如果已经配置过环境则跳过此步骤 )==

   ```bash
   # 安装node环境, npm 命令已内置到node中, 无需单独安装
   $ brew install node
   
   # 检查 node 和 npm 是否安装成功
   $ node -v
   v19.4.0
   $ npm -v
   9.4.2
   
   # 安装 TypeScript 库 (-g 参数是指将库安转到全局中, 不会安装到当前项目)
   npm install typescript -g 
   ```

3. 安装Frida相关环境

   ```bash
   # 1. 安装代理项目依赖包
   npm install --no-fund
   ```

### 2. 编译脚本

1. 手动编译

   ```bash
   # 将ts文件编译成js, 文件会写入到当前目录
   npm run build
   ```

2. 自动编译

   ```bash
   # 在运行此命令后, 当编辑 agent.ts 文件时, 监控到变更则会触发自动编译。(有一定延时)
   npm run watch
   ```

## 文件说明

| 文件          | 作用                             |
| ------------- | -------------------------------- |
| agent.ts      | 主源码文件 (编写的frida相关代码) |
| package.json  | npm 包管理配置文件               |
| tsconfig.json | TypeScript 编译配置文件          |
| README.md     | 使用说明文件                     |

## package.json 常用配置项

## tsconfig.json 常用配置项