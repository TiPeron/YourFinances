
def validateCPF(cpf:str):
    try:
        if (not type(cpf) == str):
            return False
        # Remove pontos e traços
        cpf_limpo = cpf.replace(".", "").replace("-", "")

        numeros = cpf_limpo[:10]
        dig_valid = cpf_limpo[10]

        soma = 0 
        for i, digito in enumerate(numeros):
            multiplicador = 11 - i
            soma += int(digito) * multiplicador

        # Multiplica por 10
        resultado = soma * 10

        # Obtem o resto da divisão por 11
        resto = resultado % 11
        # Determina o primeiro dígito verificador
        ult_dig = 0 if resto > 9 else resto

        if (str(ult_dig) == dig_valid):
            return True
        else:
            return False
    except:
        return False