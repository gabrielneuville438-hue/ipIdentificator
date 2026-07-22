import java.util.Scanner;
public class DecryptorSystem 
{
    public static void main(String[] args) 
    {
        Scanner input = new Scanner(System.in); //Cria um leitor de dados para ser digitado no terminal
        System.out.println("SISTEMA DE DESCRIPTOGRAFIA DE CREDENCIAIS");
        System.out.println("-----------------------------------------");
        //Pede o IP que foi usado como chave de cadeado
        System.out.print("Digite o IP do dispositivo alvo (Ex 192.168.0.1): ");
        String ipChave = input.nextLine().trim();
        //Pde para por a senha criptografada
        System.out.print("Cole o texto criptografado: ");
        String textoCriptografados = input.nextLine().trim();
        System.out.println("\n[+] Tentando descriptografar !");
        System.out.println("--------------------------------");
        //Execução da engenharia reversa do algoritmo AES
        String senhaRevelada = descriptografarSenhaComIp(textoCriptografados, ipChave);
        System.out.println("\n[+] CHAVE REVELADA:");
        System.out.println("Senha Aleatória Original: " + senhaRevelada);
        System.out.println("------------------------------------------");
        input.close();
    }
    //Função que reverte o processo AES-128 usando o Hash do IP como segredo
    private static String descriptografarSenhaComIp(String textoCriptografado, String ipKey) 
    {
        try 
        {
            //Gera o mesmo Hash SHA-256 a partir do IP para recriar a chave idêntica
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hashDoIp = digest.digest(ipKey.getBytes("UTF-8"));
            //Recorta os mesmos 16 bytes iniciais para a chave AES
            byte[] chaveAes = new byte[16];
            System.arraycopy(hashDoIp, 0, chaveAes, 0, 16);
            //Configura o motor do Java no modo de Descriptografia (DECRYPT_MODE)
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(chaveAes, "AES");
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES");
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey);
            //Transforma o texto grande (Base64) de volta em bytes puros
            byte[] bytesCriptografados = java.util.Base64.getDecoder().decode(textoCriptografado);
            //Decodifica os bytes usando a chave e reconstrói a String limpa
            byte[] bytesDescriptografados = cipher.doFinal(bytesCriptografados);
            return new String(bytesDescriptografados, "UTF-8");
        }catch(Exception e) {
            // Se o IP digitado estiver errado por um único número, o Java falha e cai aqui
            return "Acesso Negado! IP incorreto ou dados corrompidos.";
        }
    }
}