#!/bin/bash
set -e

echo "=== Avvio compilazione moduli ==="

# 1. Compile all .cpp files in the folder into object files (.o)
for src_file in *.cpp; do
    # Estrae il nome del file senza l'estensione (es. crypto.cpp -> crypto)
    obj_name="${src_file%.*}"
    
    echo "Compilazione di $src_file -> ${obj_name}.o"
    # Il flag -c istruisce g++ a compilare senza fare il linking
    g++ -std=c++17 -Wall -c "$src_file" -o "${obj_name}.o"
done

echo ""
echo "=== Avvio fase di linking (OpenSSL + Pthreads) ==="

# 2. Crea l'eseguibile del Server 
# Unisce server.o con i moduli condivisi e database.o
if [ -f "server.o" ]; then
    echo "Linking del Server..."
    g++ -std=c++17 server.o crypto.o connection.o protocol.o database.o -o server -lssl -lcrypto -pthread
fi

# 3. Crea l'eseguibile del Client 
# Unisce client.o con i moduli condivisi (escludendo database.o e server.o)
if [ -f "client.o" ]; then
    echo "Linking del Client..."
    g++ -std=c++17 client.o crypto.o connection.o protocol.o -o client -lssl -lcrypto -pthread
fi

# 4. Link the Test Server
if [ -f "test_server.o" ]; then
    echo "Linking del Test Server..."
    g++ -std=c++17 test_server.o connection.o protocol.o -o test_server -pthread
fi

# 5. Link the Test Client
if [ -f "test_client.o" ]; then
    echo "Linking del Test Client..."
    g++ -std=c++17 test_client.o connection.o protocol.o -o test_client -pthread
fi

# 6. Link the SHA-256 Test
if [ -f "test_sha256.o" ]; then
    echo "Linking del SHA-256 Test..."
    g++ -std=c++17 test_sha256.o crypto.o -o test_sha256 -lssl -lcrypto -pthread
fi

# 7. HKDF Test
if [ -f "test_hkdf.o" ]; then
    echo "Linking del HKDF Test..."
    g++ -std=c++17 test_hkdf.o crypto.o -o test_hkdf -lssl -lcrypto -pthread
fi

echo ""
echo "=== Build completata con successo! ==="