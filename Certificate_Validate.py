#!/usr/bin/env python
# coding: utf-8

# In[1]:


#!/usr/bin/env python
# coding: utf-8

# In[1]:


import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509 import Name, BasicConstraints
from cryptography.exceptions import InvalidSignature
from cryptography import x509
import datetime
import re


# In[2]:


# Function to check if a password is strong
def is_strong_password(password):
    # Password must be at least 8 characters long
    if len(password) < 8:
        return False

    # Password must contain at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False

    # Password must contain at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False

    # Password must contain at least one digit
    if not re.search(r'[0-9]', password):
        return False

    # Password must contain at least one special character (e.g., !@#$%^&*)
    if not re.search(r'[!@#$%^&*]', password):
        return False

    return True


# In[3]:


# Modify the generate_certificates function to check password strength and display verification result
def generate_certificates():
    ca_common_name = ca_common_name_entry.get()
    ca_email = ca_email_entry.get()
    ca_password = ca_password_entry.get()
    user_common_name = user_common_name_entry.get()
    user_email = user_email_entry.get()
    user_password = user_password_entry.get()

    # Check if CA password and user password meet the criteria for a strong password
    if not is_strong_password(ca_password) or not is_strong_password(user_password):
        messagebox.showerror("Password Error", "Passwords must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one digit, and one special character.")
        return

    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    ca_certificate = x509.CertificateBuilder().subject_name(ca_subject)
    ca_certificate = ca_certificate.issuer_name(ca_subject)
    ca_certificate = ca_certificate.public_key(ca_private_key.public_key())
    ca_certificate = ca_certificate.serial_number(x509.random_serial_number())
    ca_certificate = ca_certificate.not_valid_before(datetime.datetime.utcnow())
    ca_certificate = ca_certificate.not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    )
    ca_certificate = ca_certificate.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    ca_certificate = ca_certificate.sign(
        private_key=ca_private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    ca_cert_pem = ca_certificate.public_bytes(serialization.Encoding.PEM)

    user_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, user_common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, user_email)
    ])

    

    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(user_subject)
    basic_constraints = BasicConstraints(ca=False, path_length=None)
    csr_builder = csr_builder.add_extension(basic_constraints, critical=True)
    csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    received_private_key = ca_private_key
    received_ca_certificate = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())

    csr_received = x509.load_pem_x509_csr(csr_pem, default_backend())
    builder = x509.CertificateBuilder().subject_name(csr_received.subject)
    builder = builder.issuer_name(received_ca_certificate.subject)
    builder = builder.public_key(csr_received.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    received_certificate = builder.sign(
        private_key=received_private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    received_cert_pem = received_certificate.public_bytes(serialization.Encoding.PEM)

    verification_result = True
    if ca_password == user_password:
        try:
            received_ca_certificate.public_key().verify(
                received_certificate.signature,
                received_certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                received_certificate.signature_hash_algorithm,
            )
        except InvalidSignature:
            verification_result = False
    else:
        verification_result = False

    if verification_result:
        messagebox.showinfo("Verification Result", "Verification Successful")
    else:
        messagebox.showerror("Verification Result", "Verification Failed")


# In[4]:


root = tk.Tk()
root.title("Certificate Generation and Verification")

ca_common_name_label = tk.Label(root, text="Enter Common Name for CA:")
ca_common_name_label.pack()
ca_common_name_entry = tk.Entry(root)
ca_common_name_entry.pack()

ca_email_label = tk.Label(root, text="Enter Email for CA:")
ca_email_label.pack()
ca_email_entry = tk.Entry(root)
ca_email_entry.pack()

ca_password_label = tk.Label(root, text="Enter Password for CA:")
ca_password_label.pack()
ca_password_entry = tk.Entry(root, show="*")
ca_password_entry.pack()

user_common_name_label = tk.Label(root, text="Enter Common Name for User:")
user_common_name_label.pack()
user_common_name_entry = tk.Entry(root)
user_common_name_entry.pack()

user_email_label = tk.Label(root, text="Enter Email for User:")
user_email_label.pack()
user_email_entry = tk.Entry(root)
user_email_entry.pack()

user_password_label = tk.Label(root, text="Enter Password for User:")
user_password_label.pack()
user_password_entry = tk.Entry(root, show="*")
user_password_entry.pack()

generate_button = tk.Button(root, text="Generate Certificates and Verify", command=generate_certificates)
generate_button.pack()

root.mainloop()


# In[ ]:




