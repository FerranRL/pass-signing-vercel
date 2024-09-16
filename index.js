const express = require('express');
const multer = require('multer');
const openssl = require('openssl-nodejs');
const path = require('path');
const fs = require('fs');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

// Ruta para firmar el manifest.json
app.post('/api/sign', upload.single('manifest'), (req, res) => {
  try {
    const certPath = path.join(__dirname, 'certificates', 'certificado.p12'); // Certificado de pase
    const wwdrPath = path.join(__dirname, 'certificates', 'AppleWWDRCAG3.pem'); // Certificado WWDR
    
    // Verifica que los archivos existen antes de continuar
    if (!fs.existsSync(certPath) || !fs.existsSync(wwdrPath)) {
      console.error('Certificados no encontrados');
      return res.status(500).send('Certificados no encontrados');
    }

    // Guardar el manifest.json recibido en el directorio temporal
    const manifestPath = path.join('/tmp', 'manifest.json'); // Cambiado a /tmp
    fs.writeFileSync(manifestPath, req.file.buffer);

    // Ruta para guardar la firma
    const signaturePath = path.join('/tmp', 'signature.sig'); // Cambiado a /tmp
    
    const command = [
      'smime',
      '-binary',
      '-sign',
      '-certfile', wwdrPath,
      '-signer', certPath,
      '-inkey', certPath,
      '-in', manifestPath,
      '-out', signaturePath,
      '-outform', 'DER',
      '-passin', 'pass:52159514', // Cambia esta contraseña si es necesario
      //'-md', 'sha256',
    ];

    // Ejecuta el comando OpenSSL y captura cualquier error
    openssl(command, (err) => {
      if (err) {
        console.error('Error al firmar:', err);
        return res.status(500).send('Error al firmar el manifest');
      }
      
      // Verifica si la firma se generó correctamente antes de enviarla
      if (!fs.existsSync(signaturePath)) {
        console.error('La firma no fue generada correctamente');
        return res.status(500).send('La firma no fue generada correctamente');
      }

      res.sendFile(signaturePath);
    });
  } catch (error) {
    console.error('Error inesperado:', error);
    res.status(500).send('Error inesperado en el servidor');
  }

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
