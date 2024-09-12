#!/bin/bash

# 색깔 변수 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Sonic 데일리 퀘스트 스크립트를 시작합니다...${NC}"

# 작업 디렉토리 설정
work="/root/sonic-all"

# 기존 작업 디렉토리가 존재하면 삭제
if [ -d "$work" ]; then
    echo -e "${YELLOW}작업 디렉토리 '${work}'가 이미 존재하므로 삭제합니다.${NC}"
    rm -rf "$work"
fi

# 작업 디렉토리 새로 생성
echo -e "${YELLOW}새로운 작업 디렉토리 '${work}'를 생성합니다.${NC}"
mkdir -p "$work"
cd "$work"

# 파일 다운로드 및 덮어쓰기
echo -e "${YELLOW}필요한 파일들을 다운로드합니다...${NC}"

# Git 설치
echo -e "${YELLOW}Git을 설치합니다...${NC}"
sudo apt install -y git

# 존재하는 파일을 삭제하고 다운로드
echo "Git 저장소 클론 중..."
rm -rf ./*
git clone https://github.com/KangJKJK/sonic-all

# npm 설치 여부 확인
echo -e "${YELLOW}필요한 파일들을 설치합니다...${NC}"
if ! command -v npm &> /dev/null; then
    echo -e "${RED}npm이 설치되지 않았습니다. npm을 설치합니다...${NC}"
    sudo apt-get update
    sudo apt-get install -y npm
else
    echo -e "${GREEN}npm이 이미 설치되어 있습니다.${NC}"
fi

# Node.js 모듈 설치
echo -e "${YELLOW}필요한 Node.js 모듈을 설치합니다...${NC}"
npm install
npm install @solana/web3.js chalk bs58

# 개인키 입력받기
read -p "Solana의 개인키를 쉼표로 구분하여 입력하세요: " privkeys

# 개인키를 파일에 저장
echo "$privkeys" > "$work/private.txt"

# 파일 생성 확인
if [ -f "$work/private.txt" ]; then
    echo -e "${GREEN}개인키 파일이 성공적으로 생성되었습니다.${NC}"
else
    echo -e "${RED}개인키 파일 생성에 실패했습니다.${NC}"
fi

# sonic.js 스크립트 실행
echo -e "${GREEN}sonic.js 스크립트를 실행합니다...${NC}"
node --no-deprecation sonic.js

echo -e "${GREEN}모든 작업이 완료되었습니다. 컨트롤+A+D로 스크린을 종료해주세요.${NC}"
echo -e "${GREEN}스크립트 작성자: https://t.me/kjkresearch${NC}"
