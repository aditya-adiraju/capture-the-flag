
FROM sagemath/sagemath:latest

WORKDIR /ctf

RUN sage --pip install --upgrade pip

RUN sage --pip install pycryptodome

COPY solve.sage .
COPY CRSA.py .

CMD ["sage", "solve.sage"]
