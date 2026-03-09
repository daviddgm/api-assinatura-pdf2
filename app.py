import os
import shutil
import tempfile
import uuid
import traceback
import hashlib
from flask import Flask, request, jsonify, send_file

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from asn1crypto.keys import PrivateKeyInfo
from asn1crypto.x509 import Certificate
from asn1crypto.pem import unarmor
from asn1crypto import cms

from pyhanko_certvalidator.registry import SimpleCertificateStore
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.stamp import TextStampStyle
from pyhanko.sign.fields import SigFieldSpec, append_signature_field

app = Flask(__name__)
TEMP_DIR = tempfile.gettempdir()

@app.route('/preparar', methods=['POST'])
def preparar_pdf():
    try:
        pdf_file = request.files['pdf']
        cert_pem = request.form['cert_pem'].encode('utf-8') 
        nome_assinante = request.form.get('nome_assinante', 'Responsável')
        cargo = request.form.get('cargo', '')
        posicao = request.form.get('posicao', '1')
        
        id_sessao = str(uuid.uuid4())
        pdf_path = os.path.join(TEMP_DIR, f'{id_sessao}.pdf')
        dummy_pdf_path = os.path.join(TEMP_DIR, f'{id_sessao}_dummy.pdf')
        pdf_file.save(pdf_path)
        shutil.copy(pdf_path, dummy_pdf_path) # Fazemos uma cópia para trabalhar
        
        type_name, headers, der_bytes = unarmor(cert_pem)
        certificado = Certificate.load(der_bytes)
        cert_registry = SimpleCertificateStore()
        cert_registry.register(certificado)

        # GERA CHAVE FALSA GIGANTE PARA RESERVAR BASTANTE ESPAÇO NO ENVELOPE
        dummy_priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        dummy_der = dummy_priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        dummy_key = PrivateKeyInfo.load(dummy_der)
        
        # --- LÓGICA DO CARIMBO VISUAL ---
        # Define as coordenadas (Box) na folha A4.
        # Largura da folha A4 é aprox 595 pontos. A Altura (Y) começa em 0 na base.
        # 1 = Esquerda (Resp. Contratada)
        if posicao == '1':   
            box = (60, 280, 220, 330)
        # 2 = Centro (Gestor do Contrato)
        elif posicao == '2': 
            box = (220, 280, 380, 330)
        # 3 = Direita (Fiscal do Contrato)
        else:                
            box = (380, 280, 540, 330)

        # 1. CRIA O PDF COM O ENVELOPE (PKCS#7) COMPLETO, MAS ASSINATURA FALSA
        with open(dummy_pdf_path, 'rb+') as doc:
            writer = IncrementalPdfFileWriter(doc)
            nome_campo = 'Assinatura_OSE_' + id_sessao
            ultima_pagina = int(writer.prev.root['/Pages']['/Count']) - 1

            append_signature_field(writer, SigFieldSpec(sig_field_name=nome_campo, on_page=ultima_pagina, box=box))
            texto = f"ASSINADO DIGITALMENTE\nPor: {nome_assinante}\n{cargo}\nData: %(ts)s"
            stamp_style = TextStampStyle(stamp_text=texto, border_width=0, background=0)

            signer = signers.SimpleSigner(certificado, dummy_key, cert_registry)
            pdf_signer = signers.PdfSigner(
                signature_meta=signers.PdfSignatureMetadata(field_name=nome_campo, md_algorithm='sha256'),
                signer=signer,
                stamp_style=stamp_style
            )
            
            # Força o espaço a ter 16384 bytes para caber qualquer certificado
            pdf_signer.sign_pdf(writer, in_place=True, bytes_reserved=16384)
            
        # 2. EXTRAI O ENVELOPE E CALCULA O HASH VERDADEIRO A SER ASSINADO PELO USUÁRIO
        with open(dummy_pdf_path, 'rb') as f:
            pdf_data = f.read()
            
        start_idx = pdf_data.find(b'/Contents <') + 11
        end_idx = pdf_data.find(b'>', start_idx)
        cms_hex = pdf_data[start_idx:end_idx]
        cms_bytes = bytes.fromhex(cms_hex.decode('ascii'))
        
        content_info = cms.ContentInfo.load(cms_bytes)
        signed_attrs = content_info['content']['signer_infos'][0]['signed_attrs']
        
        # Padrão Internacional (RFC 5652): O Hash recai sobre os Atributos, não no documento puro
        attrs_der = signed_attrs.dump()
        attrs_der = b'\x31' + attrs_der[1:] # Converte a tag ASN.1 para SET
        hash_attrs = hashlib.sha256(attrs_der).hexdigest()

        return jsonify({
            'status': 'sucesso',
            'id_sessao': id_sessao,
            'hash_para_assinar': hash_attrs
        })

    except Exception as e:
        return jsonify({'erro': str(e), 'traceback': traceback.format_exc()}), 500


@app.route('/injetar', methods=['POST'])
def injetar_assinatura():
    try:
        id_sessao = request.form['id_sessao']
        assinatura_hex = request.form['assinatura_hex'] 
        
        dummy_pdf_path = os.path.join(TEMP_DIR, f'{id_sessao}_dummy.pdf')
        
        # 3. LÊ O PDF DUMMY NOVAMENTE E ISOLA O ENVELOPE
        with open(dummy_pdf_path, 'rb') as f:
            pdf_data = f.read()
            
        start_idx = pdf_data.find(b'/Contents <') + 11
        end_idx = pdf_data.find(b'>', start_idx)
        cms_hex = pdf_data[start_idx:end_idx]
        cms_bytes = bytes.fromhex(cms_hex.decode('ascii'))
        
        # 4. SUBSTITUI A ASSINATURA FALSA PELA REAL (VINDA DO NAVEGADOR)
        content_info = cms.ContentInfo.load(cms_bytes)
        signer_info = content_info['content']['signer_infos'][0]
        signer_info['signature'] = bytes.fromhex(assinatura_hex)
        
        new_cms_bytes = content_info.dump()
        new_cms_hex = new_cms_bytes.hex().encode('ascii')
        
        # Mantém exatamente o mesmo tamanho do buraco do PDF com preenchimento de zeros
        padding_len = len(cms_hex) - len(new_cms_hex)
        new_cms_hex += b'0' * padding_len
        
        # 5. INJETA O ENVELOPE CORRIGIDO E SALVA O ARQUIVO FINAL
        new_pdf_data = pdf_data[:start_idx] + new_cms_hex + pdf_data[end_idx:]
        
        out_path = os.path.join(TEMP_DIR, f'{id_sessao}_final.pdf')
        with open(out_path, 'wb') as f:
            f.write(new_pdf_data)
            
        return send_file(out_path, as_attachment=True, download_name='assinado.pdf', mimetype='application/pdf')

    except Exception as e:
        return jsonify({'erro': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
