# Client-Server Implementation 🚀

This repository contains a simple client-server implementation in C++ using sockets. The server can handle multiple clients concurrently, and clients can request files from the server or check the last access time of a file.

## Features ✨

- Concurrent handling of multiple clients
- File retrieval (`MyGet`)
- Last access time check (`MyLastAccess`)
- Error handling for invalid commands and arguments

## Getting Started 🛠️

### Prerequisites 📋

- Docker
- Docker Compose

### Installation and Setup ⚙️

1. **Clone the repository**:
    ```sh
    git clone <span style="color:red">PUT TEXT</span>.
    cd client-server
    ```

- **From here on, you have two options:** 
    2.1. **Compile the server and client code and run in multiple terminals**:
      ```sh
      g++ -o server server.cpp -lpthread
      g++ -o client client.cpp
      ```

    2.2. **Build and run the Docker containers**:
      ```sh
      docker-compose up --build
      ```

It is recommended that you use Docker. The following instructions are for docker utilization.

### Running the Clients 🖥️

1. **Open a terminal and attach to `client1`**:
    ```sh
    docker exec -it client1 bash
    ```

2. **Open another terminal and attach to `client2`**:
    ```sh
    docker exec -it client2 bash
    ```

### Running Tests 🧪

#### From `client1` Terminal

1. **Test Misspelled Command**:
    ```sh
    ./client server MyGt test_1.txt
    ```

2. **Test Invalid Command**:
    ```sh
    ./client server InvalidCommand test_1.txt
    ```

3. **Test Missing Arguments**:
    ```sh
    ./client server MyGet
    ```

4. **Test Excess Arguments**:
    ```sh
    ./client server MyGet test_1.txt extra_arg
    ```

5. **Test Missing Server Name**:
    ```sh
    ./client MyGet test_1.txt
    ```

6. **Test Valid `MyGet` Command**:
    ```sh
    ./client server MyGet test_1.txt
    ```

7. **Test Valid `MyGet` Command with Different File**:
    ```sh
    ./client server MyGet test_2.md
    ```

#### From `client2` Terminal

1. **Test Valid `MyLastAccess` Command**:
    ```sh
    ./client server MyLastAccess
    ```

2. **Test Valid `MyLastAccess` Command After `MyGet`**:
    ```sh
    ./client server MyGet test_folder/test.txt
    ./client server MyLastAccess
    ```
3. **Test access to directory files**:
    ```sh
    ./client server MyGet test_folder/CSC-35_Course_Presentation.pdf
    ```

## Acknowledgments 🙏

- Thanks to Denys Derlian and Rafael Hoffmann for their support in this work.

---

Happy coding! 💻