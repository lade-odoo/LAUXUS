#!/bin/sh
mount_dir=../mount
lauxus_exec=../app
passthrough_exec=fuse_passthrough/passthrough


activate_LAUXUS() {
  echo "COMPILING LAUXUS ..."
  cd ".." && make clean && make > "/dev/null" 2> "/dev/null" && cd "Benchmarks"

  echo "CREATING the Filesystem ..."
  $lauxus_exec --create_fs --new_username=root --auditor_username=auditor > "/dev/null" 2> "/dev/null"

  echo "LAUNCHING the Filesystem ..."
  $lauxus_exec -f $mount_dir --user_uuid=0000-00-00-00-000000 &
  sleep 5
}
activate_PASSTHROUGH() {
  echo "COMPILING PASSTHROUGH ..."
  cd "fuse_passthrough" && gcc -Wall passthrough.c `pkg-config fuse --cflags --libs` -o passthrough > "/dev/null" 2> "/dev/null" && cd ".."

  echo "LAUNCHING the Filesystem ..."
  $passthrough_exec -f $mount_dir &
  sleep 5
}
deactivate_FUSE() {
  fusermount -u $mount_dir > "/dev/null" 2> "/dev/null"
}


echo "====================== LAUXUS ======================"
deactivate_FUSE
activate_LAUXUS
echo "[LAUXUS] Per block ..."
python3 benchmark.py PER_BLOCK LAUXUS
echo "[LAUXUS] Per size ..."
python3 benchmark.py PER_SIZE LAUXUS
echo "[LAUXUS] Per block size ..."
python3 benchmark.py PER_BLOCK_SIZE LAUXUS
echo "[LAUXUS] Per offset write position ..."
python3 benchmark.py PER_OFFSET_WRITE LAUXUS
echo "[LAUXUS] Per folder depth ..."
python3 benchmark.py PER_FOLDER_DEPTH LAUXUS

echo "====================== NOTHING ======================"
deactivate_FUSE
echo "[NOTHING] Per block ..."
python3 benchmark.py PER_BLOCK NOTHING
echo "[NOTHING] Per size ..."
python3 benchmark.py PER_SIZE NOTHING
echo "[NOTHING] Per block size ..."
python3 benchmark.py PER_BLOCK_SIZE NOTHING
echo "[NOTHING] Per offset write position ..."
python3 benchmark.py PER_OFFSET_WRITE NOTHING
echo "[NOTHING] Per folder depth ..."
python3 benchmark.py PER_FOLDER_DEPTH NOTHING


echo "Cleaning ..."
rm -rf $mount_dir/*
rm /tmp/benchmark1.txt
