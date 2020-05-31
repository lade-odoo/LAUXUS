#!/bin/sh
mount_dir=../mount
lauxus_exec=../lauxus


activate_LAUXUS() {
  echo "COMPILING LAUXUS ..."
  cd ".." && make clean && make > "/dev/null" 2> "/dev/null" && cd "Benchmarks"

  echo "CREATING the Filesystem ..."
  $lauxus_exec --new_fs > "/dev/null" 2> "/dev/null"

  echo "LAUNCHING the Filesystem ..."
  $lauxus_exec -f $mount_dir --u_uuid=0000-00-00-00-000000 &
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
rm $mount_dir/*
