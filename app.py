import os
import tempfile
import uuid
import traceback
from flask import Flask, request, jsonify, send_file

# --- A GRANDE MUDANÇA: Usamos a biblioteca raiz para ler o certificado ---
from asn1crypto.x509 import Certificate
from asn1crypto.pem import unarmor

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
        
        # Lê o certificado PEM diretamente da memória usando asn1crypto
        type_name, headers, der_bytes = unarmor(cert_pem)
        certificado = Certificate.load(der_bytes)
        
        # Coordenadas do carimbo
        if posicao == '1': box = (40, 380, 190, 440)
        elif posicao == '2': box = (222, 380, 372, 440)
        else: box = (405, 380, 555, 440)

        with open(pdf_path, 'rb+') as doc:
            writer = IncrementalPdfFileWriter(doc)
            nome_campo = 'Assinatura_OSE_' + id_sessao
            ultima_pagina = int(writer.prev.root['/Pages']['/Count']) - 1

            # Cria o espaço de assinatura no PDF
            append_signature_field(writer, SigFieldSpec(sig_field_name=nome_campo, on_page=ultima_pagina, box=box))
            
            # Estilo do carimbo visual
            texto = f"✓ ASSINADO DIGITALMENTE\nPor: {nome_assinante}\n{cargo}\nData: %(ts)s"
            stamp_style = TextStampStyle(stamp_text=texto, border_width=0, background_alpha=0)

            # Instancia o Signer passando diretamente o objeto certificado
            signer = signers.SimpleSigner(
                signing_cert=certificado, 
                signing_key=None
            )
            
            pdf_signer = signers.PdfSigner(
                signature_meta=signers.PdfSignatureMetadata(field_name=nome_campo, md_algorithm='sha256'),
                signer=signer,
                stamp_style=stamp_style
            )
            
            # Prepara o documento e extrai o Hash sem assinar
            prep_digest, validation_info, output_stream = pdf_signer.digest_doc_for_signature(writer)
            
            # Guarda o ficheiro com o "buraco" da assinatura
            with open(os.path.join(TEMP_DIR, f'{id_sessao}_pendente.pdf'), 'wb') as f:
                f.write(output_stream.getbuffer())
                
            hash_documento = prep_digest.document_digest.hex()

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
        id_sessao = request.form['id_sessao']
        assinatura_hex = request.form['assinatura_hex'] 
        
        pendente_path = os.path.join(TEMP_DIR, f'{id_sessao}_pendente.pdf')
        out_path = os.path.join(TEMP_DIR, f'{id_sessao}_final.pdf')
        
        assinatura_bytes = bytes.fromhex(assinatura_hex)
        
        # ATENÇÃO: Deixei comentado a injeção antiga pois validaremos o fluxo primeiro!
        # with open(pendente_path, 'rb') as doc_in:
        #    with open(out_path, 'wb') as doc_out:
        #        signers.PdfSigner.fill_external_signature(doc_in, doc_out, assinatura_bytes)
                
        return jsonify({'erro': 'Aviso: Preparação e JavaScript passaram com sucesso! Rota de Injeção em Manutenção.'}), 500

    except Exception as e:
        return jsonify({'erro': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
