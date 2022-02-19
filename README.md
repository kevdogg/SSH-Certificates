# **How to Create SSH Host(Server) and Client Certificates**

## **Create CA (Certificate Authority) Public and Private Key**

Usually I place place the SSH CA authority private and public keys within /etc/ssl/ssl folder.

My directory structure is as follows:
```bash
/etc/ssl/ssh
├── CA
├── CA.pub
├── clients <-Directory
├── hosts   <-Directory
```

This directory contains the SSH Certificate Authority's  CA public and private keys to be used for SSH Certificates.


These keys represent SSH Certificate Authority - or ROOT CA for SSH keys within the *.domain.com domain.

The CA private/public keypair can generated via the following command:
    ssh-keygen -a 100 -t ed25519 -f CA -C domain.com-SSH-CA


## **HOST CERTIFICATES**

### **HOST CERTIFICATES BACKGROUND**

During the process of installing the ssh daemon. ssh host keys are automatically generated and are created within the /etc/ssh diretory.
Typically the keys that are generated are the following:

  - ssh_host_dsa_key / ssh_host_dsa_key.pub
  - ssh_host_ecdsa_key / ssh_host_ecdsa_key.pub
  - ssh_host_ed25519_key / ssh_host_ed25519_key.pub
  - ssh_host_rsa_key / ssh_host_rsa_key.pub

Depending on what type of keys (dsa,rsa,ecdsa,ed25519) are being used to access the server (or host) the corresponding Host Public Key needs to be signed by the SSH CA Private Key.  If only ed25519 keys are being used, only the ssh_host_ed25519_key.pub needs to be signed.  If using older methods like rsa are being used by client keys, then the ssh_host_rsa_key.pub also needs to be signed by the SSH CA Private Key.

 ### **HOST CERTIFICATES STEP #1 - Sign host public keys and create host certificates**

&nbsp;&nbsp;&nbsp;&nbsp;Signing the Host's Public Key will create a SSH Host Certificate.  Host SSH certifcates are created using the following command:

    ssh-keygen -h -s CA -n LIST-OF-PRINCIPALS -I ID -V <Validity Time> -z <SERIAL_NUMBER> KEYFILE.pub

<div style="padding-left: 10%">
&nbsp;&nbsp;&nbsp;&nbsp;-h - Indicates this is a Host Key to be signed (Client keys don't have this flag)<BR />
&nbsp;&nbsp;&nbsp;&nbsp;-s - This is the private SSH Certificate Authority's CA key file<BR />
&nbsp;&nbsp;&nbsp;&nbsp;-I  ID - short, human-readable description of the certificate (Optional)<BR />
&nbsp;&nbsp;&nbsp;&nbsp;-V <Validity Time> - This (optional) flag gives an expiration date of the Host's SSH Certificate.  +52w is used as an example<BR />
&nbsp;&nbsp;&nbsp;&nbsp;-z - Serial Number<BR />
&nbsp;&nbsp;&nbsp;&nbsp;-n  LIST-OF_PRINCIPALS - comma-separated list of the domain names by which the Server is accessed. For example: archbw,archbw.domain.com,<BR />
</div>  
<BR /><br>
  Running the above command will result in a file known as **KEYFILE-cert.pub**.  This command needs to be run for each type of server host key that needs to be signed (ed25519,ecdsa,rsa,dsa).

  I will usually run the following command within the /etc/ssh directory for only the ssh_host_ed25519_key.pub file:

    ssh-keygen -h -s CA -n <LIST-OF-PRINCIPALS> -I <Description with No Spaces> -z <Serial Number> ssh_host_ed25519_key.pub

  The above command will produced a file known as /etc/ssh/ssh_host_ed25519_key-cert.pub

  To Validate the Host/Server Certificate use:

    ssh-keygen -Lf /etc/ssh/ssh_host_ed25519_key-cert.pub

### **HOST CERTIFICATES STEP #2 - Configure the Server's SSH Daemon (sshd) to use the Host Certificate(s) created in Step #1*

&nbsp;&nbsp;&nbsp;&nbsp;Add the following within ***/etc/ssh/sshd_config***

    HostCertificate **/etc/ssh/KEYFILE-cert.pub

  **KEYFILE** will be: ssh_host_ed25519_key, ssh_host_rsa_key, ssh_host_ecdsa_key, ssh_host_dsa_key.<br><br>
  I believe you can repeat the HostCertificate line multiple times in the config files to specficy Multiple Host Certificates of different types (dsa,rsa,ecdsa,ed25519).  The HostCertificate(s) should always have a corresponding HostKey entry within the /etc/ssh/sshd_config file.

### **HOST CERTIFICATES STEP #3 - Configure each SSH Client to trust the SSH Certificate Authority's Public Key**

&nbsp;&nbsp;&nbsp;&nbsp;Each client will have a /etc/.ssh/known_hosts file and global /etc/ssh/ssh_known_hosts. You'll want to remove lines such as the following if wanting to use SSH Client/Server Certificates rather than SSH KeyBased Authentication.  Remove lines corresponding to each Server that will be using a SSH Host Certificate:

    10.0.1.86 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM5VdFpCiEm5PB/1pycQ/VI6pMFQU87NHGHQWXveNNSX

Instead of Host Keys, include the CA.pub in the known_hosts on each Client. So for example:

    @cert_authority LIST-OF-SERVERS <CA.pub>

&nbsp;&nbsp;&nbsp;&nbsp;- LIST-OF-SERVERS - comma-separate list of Servers that signed their host key. Wildcards can be permitted.

&nbsp;&nbsp;&nbsp;&nbsp;- CA.pub - This is the SSH Certificate Authority's CA.pub key.

    @cert-authority archbw,*.domain.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGHQYA5QkxrnJUO4M2t3TjzrRUVIWAlFQ/7ADlPq4s7T domain.com-SSH-CA


## **USER/Client CERTIFICATES**

### **User/Client Certificates Background**

&nbsp;&nbsp;&nbsp;&nbsp;Each user is going to generate their individual ssh keypairs. This is going to be done via the following:

    ssh-keygen -o -a 100 -t ed25519 -C "<Whatever Comment You Want Here>"

This is going to produce a private/public keypair:
  
&nbsp;&nbsp;&nbsp;&nbsp;$HOME/.ssh/id_ed25519<br>
&nbsp;&nbsp;&nbsp;&nbsp;$HOME/.ssh/ed_ed25519.pub

### **USER CERTIFICATES STEP #1 - Sign the client's public key with the SSH Certificate Authority's Private Key**

The user's public key is going to be signed via the following command:

    ssh-keygen -s CA -I <ID> -n <USERNAME> -V <Validity Time> <KEYFILE>.pub

&nbsp;&nbsp;&nbsp;&nbsp;-s - This is the SSH Certificate Authority's CA private key<br>
&nbsp;&nbsp;&nbsp;&nbsp;-I - Short human readable description of certificate - no spaces (Optional)<br>
&nbsp;&nbsp;&nbsp;&nbsp;-n - Username by which you will connect -- usually the user has to have an account on the remote server<br>
&nbsp;&nbsp;&nbsp;&nbsp;-V <Validity Time>- (Optional) time indicating when certificate will expire, ie +52w<br>
&nbsp;&nbsp;&nbsp;&nbsp;\<KEYFILE\>.pub - User's public key usually id_ed25519.pub or id_rsa.pub<br>

 The SSH User Certificate needs to be stored on the client -- usually within ~/.ssh.  The name of this file will be ***KEYFILE-cert.pub*** where KEYFILE will be:  id_ed25519/id_rsa/id_dsa/id_ecdsa.

  A specific example of using this command is given below:

    ssh-keygen -a 100 -s CA -I kevdog@kevdog-MBP-2022-SSH-Client-Certificate -n kevdog id_25519.pub

The SSH User Certificate can be validated via:

    ssh-keygen -LF <Certifiate File>

&nbsp;&nbsp;&nbsp;&nbsp;- \<Certificate File\> - Will usually be id_ed25519-cert.pub

### **USER CERTIFICATES STEP #2 - Install/Copy the SSH Certificate Authority's CA public key on the server**

&nbsp;&nbsp;&nbsp;&nbsp;Copy the Server's SSH Certificate Authority's ***CA.pub*** key  ->to the Server's /etc/ssh/CA.pub

### **USER CERTIFICATES STEP #3 - Tell the Server's SSH Daemon (sshd) where to find the CA's public key**

&nbsp;&nbsp;&nbsp;&nbsp;On each SSH Host/Server, modify /etc/ssh/sshd_config to add the following:

    TrustedUserCAKeys /etc/ssh/CA.pub

### **USER CERTIFICATES #4 - Modify authorized_keys file to remove the client's public key (OPTIONAL)**

&nbsp;&nbsp;&nbsp;&nbsp;Remove any entry within the ~/.ssh/authorized_keys file on the Server.  This wwill force the server to accept client SSH certificates that are signed via the SSH CA. If you want to keep continuing to use traditional ssh client public/private keypair authentication, You don't necessarily need to remove reference to the client's public key. 

When testing the connection via the client to server, you can view the server logs via:

    sudo journalctl -u sshd -e

The log should spit out something similar to the following:

    Accepted publickey for kevdog from 10.0.1.185 port 63746 ssh2: ED25519-CERT SHA256:qC/ckN+0cZ0h/rqtL59pfSXsgQ6JZfDCzl93tWVDKbg ID kevdog@kevdog-MBP-2022-SSH-Client-Certificate (serial 0) CA ED25519 SHA256:bSSV3CEqcBTff1GGQtxvcnrM+LOzDYB+79i1CRMJQx8

## **References**
&nbsp;&nbsp;&nbsp;&nbsp;[1]: https://berndbausch.medium.com/ssh-certificates-a45bdcdfac39<br>
&nbsp;&nbsp;&nbsp;&nbsp;[2]: /etc/ssh/sshd-config additions:  
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;TrustedUserCAKeys /etc/ssh/CA.pub

