const express = require('express');
const multer = require('multer');
const openssl = require('openssl-nodejs');
const path = require('path');
const fs = require('fs');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

// Ruta para firmar el manifest.json
app.post('/api/sign', upload.single('manifest'), (req, res) => {
  // Ruta a los certificados (debes asegurar estos certificados en tu entorno de servidor)
  const certPath = path.join(__dirname, 'certificates', 'certificado.p12'); // Certificado de pase
  const wwdrPath = path.join(__dirname, 'certificates', 'AppleWWDRCAG3.pem'); // Certificado WWDR
  
  // Guardar el manifest.json recibido
  const manifestPath = path.join(__dirname, 'manifest.json');
  fs.writeFileSync(manifestPath, req.file.buffer);

  // Ruta para guardar la firma
  const signaturePath = path.join(__dirname, 'signature.sig');

  // Comando OpenSSL para firmar el manifest
  const command = [
    'smime',
    '-binary',
    '-sign',
    '-certfile',
    wwdrPath,
    '-signer',
    certPath,
    '-inkey',
    certPath,
    '-in',
    manifestPath,
    '-out',
    signaturePath,
    '-outform',
    'DER',
    '-passin',
    'pass:52159514', // Reemplaza PASSWORD con la contraseña de tu .p12
    //'-md', 'sha256',
  ];

  // Ejecuta el comando OpenSSL
  openssl(command, (err) => {
    if (err) {
      console.error('Error al firmar:', err);
      res.status(500).send('Error al firmar el manifest');
      return;
    }

    // Envía la firma de vuelta al cliente
    res.sendFile(signaturePath);
  });
});

// Inicia el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor de firma en ejecución en http://localhost:${PORT}`);
});
