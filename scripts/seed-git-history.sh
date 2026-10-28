#!/bin/sh
# ============================================================
# 制造"Git历史密钥泄露"演示场景
# 用途：模拟真实场景——密钥曾被提交，后来删除了文件，
#       但密钥仍留在Git历史中。密钥扫描引擎扫描完整历史
#       即可发现（这正是它区别于普通文本搜索的价值）。
#
# 用法：在已 git init 并完成首次提交的仓库根目录执行：
#   sh scripts/seed-git-history.sh
# ============================================================
set -e

git config user.email  "dev1@demo-company.com"
git config user.name   "dev1"

# 1. 模拟开发人员误将云配置（含AccessKey）提交入库
cat > src/main/resources/secret.properties << 'EOF'
# 云存储配置（误提交）
oss.endpoint=https://oss.demo-company.com
oss.access-key=AKIDhIsToRyLeAkEdKeY987654321
oss.secret=historical-secret-do-not-use
EOF
git add -A
git commit -m "temp: add cloud config"

# 2. 发现失误后删除文件再提交（但历史里已经有了）
git rm -q src/main/resources/secret.properties
git commit -m "remove config file"

echo ""
echo "✅ Git历史泄露场景已制造完成："
echo "   密钥 AKIDhIsToRyLeAkEdKeY987654321 存在于历史提交中，"
echo "   当前工作区已删除。密钥扫描引擎仍可从历史中发现它。"
echo "   执行 git log --oneline 查看提交记录确认。"
