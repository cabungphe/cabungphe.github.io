echo $FLAG > /flag.txt

rm -f fantiky_shop.c
rm -f docker-entrypoint.sh

socat TCP-LISTEN:5364,reuseaddr,fork EXEC:"./fantiky_shop"