echo "[!] EDIT THIS FILE FIRST!!!" # Modify the ZEROMON_FOLDER and CUCKOO_FOLDER vars, and remove this line
ZEROMON_FOLDER="/cuckoo/zer0m0n"
CUCKOO_FOLDER="/cuckoo/cuckoo"
echo "[+] GIT PULL"
cd $ZEROMON_FOLDER
git checkout master
git pull
echo "[+] SIGNATURES UPDATE"
cp ./signatures/* $CUCKOO_FOLDER/modules/signatures/
echo "[+] ZEROMON UPDATE"
cd bin
cp zer0m0n.sys $CUCKOO_FOLDER/analyzer/windows/dll/
cp logs_dispatcher.exe $CUCKOO_FOLDER/analyzer/windows/dll/
echo "[+] CUCKOO PATCH UPDATE"
mkdir /tmp/temp_cuckoo
unzip cuckoo_files.zip -d /tmp/temp_cuckoo/
cp -r /tmp/temp_cuckoo/* $CUCKOO_FOLDER
rm -rf /tmp/temp_cuckoo/
echo "[+] UPDATED, don't forget restarting cuckoo ;]"
