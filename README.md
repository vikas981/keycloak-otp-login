# keycloak-otp-login
---

### Steps to use this Keycloak SPI
- mvn clean package
- copy jar file from target to keycloak providers directory
- start/restart keycloak kc.sh or from docker container
- Login to admin console and select realm.
- Go to authentication and create duplicate from browser
- Delete Username and password from newly created browser authentication
