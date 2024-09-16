const express = require('express');
const multer = require('multer');
const forge = require('node-forge');
const path = require('path');
const fs = require('fs');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

// Ruta para firmar el manifest.json
app.post('/api/sign', upload.single('manifest'), (req, res) => {
  // Ruta a los certificados (asegúrate de tener los certificados necesarios en tu entorno de servidor)
  const certPath = path.join(__dirname, 'certificates', 'certificado.p12'); // Certificado de pase en formato .p12
  const wwdrPath = path.join(__dirname, 'certificates', 'AppleWWDRCAG3.pem'); // Certificado WWDR
  
  try {
    // Leer el manifest recibido desde la solicitud
    const manifestBuffer = req.file.buffer;

    // Leer el certificado y la clave privada del archivo .p12
    const p12Buffer = fs.readFileSync(certPath);
    const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'), false);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, '52159514'); // Reemplaza '52159514' con la contraseña de tu archivo .p12

    // Extraer el certificado y la clave privada del archivo .p12
    let cert, key;
    p12.safeContents.forEach((content) => {
      content.safeBags.forEach((bag) => {
        if (bag.cert) {
          cert = bag.cert;
        }
        if (bag.key) {
          key = bag.key;
        }
      });
    });

    if (!cert || !key) {
      console.error('Error: No se pudo extraer el certificado o la clave privada.');
      return res.status(500).send('Error al extraer el certificado o la clave privada.');
    }

    // Crear un contenedor PKCS#7 y añadir el manifest
    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(manifestBuffer.toString('binary'), 'binary');

    // Añadir el certificado y el firmante
    p7.addCertificate(cert);
    p7.addSigner({
      key: key,
      certificate: cert,
      digestAlgorithm: forge.pki.oids.sha256,
      authenticatedAttributes: [
        {
          type: forge.pki.oids.contentType,
          value: forge.pki.oids.data,
        },
        {
          type: forge.pki.oids.messageDigest,
        },
        {
          type: forge.pki.oids.signingTime,
          value: new Date(),
        },
      ],
    });

    // Firmar el contenido
    p7.sign();

    // Convertir la firma a formato DER
    const derBuffer = forge.asn1.toDer(p7.toAsn1()).getBytes();

    // Enviar la firma de vuelta al cliente
    res.set('Content-Type', 'application/octet-stream');
    res.send(Buffer.from(derBuffer, 'binary'));
  } catch (error) {
    console.error('Error inesperado:', error);
    res.status(500).send('Error al firmar el manifest');
  }
});

// Inicia el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor de firma en ejecución en http://localhost:${PORT}`);
});
