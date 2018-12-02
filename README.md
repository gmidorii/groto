# groto

## Overview

groto protocol implemented in Go.


## groto protocol
### packet spec
1. init request
```
|-----------------------------|
| 1byte | request (0x05)      |
|-----------------------------|
```

2. init response
```
|-----------------------------------------|
| 1byte  | result (OK=0x06, NG=0x06)      |
| 3byte  | version ex)1.0.0               |
| 10byte | request ID                     |
| 20byte | hash key for password          |
|-----------------------------------------|
```

3. authentication request
```
|------------------------|
| 3byte  | version       |
| 10byte | request ID    |
| 10byte | user ID       |
| 32byte | password      |
|------------------------|
```

4. authentication response
```
|------------------------------------------|
| 3byte  | version                         |
| 10byte | request ID                      |
| 1byte  | authn result (OK=0x06, NG=0x06) |
|------------------------------------------|
```
