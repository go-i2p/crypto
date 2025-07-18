#! /usr/bin/env sh

dirs=$(find aes/  chacha20/  curve25519/  dsa/  ecdsa/  ecies/  ed25519/  elg/  hkdf/ rand/  hmac/  rsa/  tunnel/ types/ -type d)
for dir in $dirs; do
    files=$(find "$dir" -maxdepth 2 -type f -name "*.go" -not -name "fuzz")
    #echo "Files in $dir: $files"
    file=$(echo $files | awk '{print $1}')
    if [ -z "$file" ]; then
        echo "no go files, skipping"
        continue
    fi
    packageLine=$(grep -E "^package" $file)
    package=$(echo $packageLine | awk '{print $2}')
    echo "Generating callgraph for $package"
    go-callvis -nostd -focus "$package" -group type -format svg -file $dir/$package "github.com/go-i2p/crypto/$dir"
    godocdown -template template.md -o "$dir/README.md" "./$dir"
    git add -v "$dir/README.md"
    git add -v "$dir/$package.svg" "$dir/README.md"
done