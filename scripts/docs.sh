#!/bin/bash
# Usage ./docs.sh <repo> <virtualenv>
main(){
  directory=$1
  venv=$2

  cd $directory
  cargo doc
  echo '<meta http-equiv=refresh content=0;url=capabilities/index.html>' > target/doc/index.html 
  if [ -d "$venv" ]; then
    source $venv/bin/activate
  else
    virtualenv $venv
    pip install ghp-import
  fi
  ghp-import -n target/doc
  git push -u origin gh-pages
 }

main $@
