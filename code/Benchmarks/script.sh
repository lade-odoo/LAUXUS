#!/bin/sh
mount_dir=../mount
lauxus_exec=../lauxus
passthrough_exec=./fuse_passthrough
passthrough_target_dir=../mount/tmp/


activate_LAUXUS() {
  echo "COMPILING LAUXUS ..."
  cd ".." && make clean && make > "/dev/null" 2> "/dev/null" && cd "Benchmarks"

  echo "CREATING the Filesystem ..."
  $lauxus_exec --new_fs > "/dev/null" 2> "/dev/null"

  echo "LAUNCHING the Filesystem ..."
  $lauxus_exec -s -f $mount_dir --u_uuid=0000-00-00-00-000000 &
  sleep 5
}
activate_PASSTHROUGH() {
  echo "COMPILING PASSTHROUGH ..."
  gcc -Wall fuse_passthrough.c `pkg-config fuse --cflags --libs` -o fuse_passthrough

  echo "LAUNCHING the Filesystem ..."
  $passthrough_exec -s -f $mount_dir &
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
echo "[LAUXUS] Per file size small write ..."
python3 benchmark.py PER_FILE_SIZE_SMALL_WRITE LAUXUS

echo "====================== PASSTHROUGH ======================"
deactivate_FUSE
activate_PASSTHROUGH
echo "[PASSTHROUGH] Per block ..."
python3 benchmark.py PER_BLOCK PASSTHROUGH $passthrough_target_dir
echo "[PASSTHROUGH] Per size ..."
python3 benchmark.py PER_SIZE PASSTHROUGH $passthrough_target_dir
echo "[PASSTHROUGH] Per block size ..."
python3 benchmark.py PER_BLOCK_SIZE PASSTHROUGH $passthrough_target_dir
echo "[PASSTHROUGH] Per offset write position ..."
python3 benchmark.py PER_OFFSET_WRITE PASSTHROUGH $passthrough_target_dir
echo "[PASSTHROUGH] Per folder depth ..."
python3 benchmark.py PER_FOLDER_DEPTH PASSTHROUGH $passthrough_target_dir
echo "[PASSTHROUGH] Per file size small write ..."
python3 benchmark.py PER_FILE_SIZE_SMALL_WRITE PASSTHROUGH $passthrough_target_dir

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
echo "[NOTHING] Per file size small write ..."
python3 benchmark.py PER_FILE_SIZE_SMALL_WRITE NOTHING


echo "Cleaning ..."
rm -rf $mount_dir/*
