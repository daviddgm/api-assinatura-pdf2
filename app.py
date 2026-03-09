import os
import tempfile
import uuid
import traceback
from flask import Flask, request, jsonify, send_file

from asn1crypto.x509 import Certificate
from asn1crypto.pem import unarmor
from pyhanko_certvalidator.registry import SimpleCertificateStore

from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.stamp import TextStampStyle
from pyhanko.sign.fields import SigFieldSpec, append_signature_field

app = Flask(__name__)
TEMP_DIR = tempfile.gettempdir()

# --- ROTA 1: PREPARA O PDF E GERA O HASH ---
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
        pdf_file.save(pdf_path)
        
        # 1. Lê o certificado da memória sem falhas
        type_name, headers, der_bytes = unarmor(cert_pem)
        certificado = Certificate.load(der_bytes)
        
        # 2. Cria o Cofre e regista o certificado
        cert_registry = SimpleCertificateStore()
        cert_registry.register(certificado)
        
        if posicao == '1': box = (60, 280, 220, 330)
        elif posicao == '2': box = (220, 280, 380, 330)
        else: box = (380, 280, 540, 330)

        with open(pdf_path, 'rb+') as doc:
            writer = IncrementalPdfFileWriter(doc)
            nome_campo = 'Assinatura_OSE_' + id_sessao
            ultima_pagina = int(writer.prev.root['/Pages']['/Count']) - 1

            append_signature_field(writer, SigFieldSpec(sig_field_name=nome_campo, on_page=ultima_pagina, box=box))
            
            texto = f"✓ ASSINADO DIGITALMENTE\nPor: {nome_assinante}\n{cargo}\nData: %(ts)s"
            stamp_style = TextStampStyle(stamp_text=texto, border_width=0, background=0)

            # A CORREÇÃO MESTRA: Passamos os 3 itens obrigatoriamente na ordem (Certificado, Chave[Nula], Cofre)
            signer = signers.SimpleSigner(certificado, None, cert_registry)
            
            # ... (código anterior) ...
            pdf_signer = signers.PdfSigner(
                signature_meta=signers.PdfSignatureMetadata(field_name=nome_campo, md_algorithm='sha256'),
                signer=signer,
                stamp_style=stamp_style
            )
            
            # A CORREÇÃO DE OURO (Sugerida pelo próprio Python): 
            # Trocamos "_signature" por "_signing"
            resultado = pdf_signer.digest_doc_for_signing(writer)
            
            # Tratamento blindado: funciona quer a biblioteca devolva Tupla ou Objeto
            if isinstance(resultado, tuple):
                prep_digest, validation_info, output_stream = resultado
                hash_documento = prep_digest.document_digest.hex()
            else:
                output_stream = resultado.output_stream
                hash_documento = resultado.document_digest.hex()
            
            # Guarda o ficheiro com o "buraco" da assinatura
            with open(os.path.join(TEMP_DIR, f'{id_sessao}_pendente.pdf'), 'wb') as f:
                f.write(output_stream.getbuffer())

        return jsonify({
            'status': 'sucesso',
            'id_sessao': id_sessao,
            'hash_para_assinar': hash_documento
        })

    except Exception as e:
        return jsonify({'erro': str(e), 'traceback': traceback.format_exc()}), 500

# --- ROTA 2: INJETA A ASSINATURA E LACRA O PDF ---
@app.route('/injetar', methods=['POST'])
def injetar_assinatura():
    try:
        # Mantendo em manutenção para validarmos a Fase 1!
        return jsonify({'erro': 'Aviso: Preparação e JavaScript passaram com sucesso! Rota de Injeção em Manutenção.'}), 500
    except Exception as e:
        return jsonify({'erro': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
