# -------------------------------------
# Based on
# -------------------------------------
FROM python:3.8

# -------------------------------------
# INFO
# -------------------------------------
LABEL author="Alberto Serra"
LABEL author_nickname=""
LABEL project="Flask Registration Login API - local"
LABEL version = "1.0.0"

# -------------------------------------
# Setup the working Directory
# -------------------------------------
RUN mkdir -p /webapp
WORKDIR /webapp/

# -------------------------------------
# Copy the webApp Code
# -------------------------------------
COPY ./ ./

# -------------------------------------
# Install the requirements
# -------------------------------------
RUN pip install -r requirements.txt
