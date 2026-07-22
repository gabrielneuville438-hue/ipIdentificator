public class PasswordGenerator 
{
    //Definição dos grupos de caracteres permitidos em senhas seguras  
    private static final String MINUSCULAS = "abcdefghijklmnopqrstuvwxyz";
    private static final String MAIUSCULAS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String NUMEROS = "0123456789";
    private static final String SIMBOLOS = "!@#$%^&*()-_=+[{]};:,<.>/?";

    //Junta todos os caracteres em um único banco de dados
    private static final String TODO_OS_CARACTERES = MINUSCULAS + MAIUSCULAS + NUMEROS + SIMBOLOS;

    public static void main(String[] args) 
    {
        int tamanhoDaSenha = 16; //Tamanho padrão recomenda pela cibersegurança
        System.out.println("Gerador de Senhas Criptograficamente Seguro");
        System.out.println("-------------------------------------------");
        String senhaGerada = gerarSenhaSegura(tamanhoDaSenha); //Gera a senha forte
        System.out.println("[+] Senha gerada com sucesso:");
        System.out.println("Aqui -> " + senhaGerada);
        System.out.println("-------------------------------------------");
        //Envio da senha gerada direto para a Área de transferência (clipboard)
        try {
            //Converte a String da senha em um objeto de textotransferível
            java.awt.datatransfer.StringSelection selecao = new java.awt.datatransfer.StringSelection(senhaGerada);
            //Pega o controle da Área de Transferência do SO
            java.awt.datatransfer.Clipboard clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selecao, null); //Injeta a senha lá dentro, sendo possível usar o Ctrl + V
            System.out.println("Copiado automaticamente! Pode dar Ctrl+V onde quiser.");
        }catch(Exception e) {
            System.out.println("Não foi possível copiar para a área de transferência.");
        }
    }

    private static String gerarSenhaSegura(int tamanho) 
    {
        //Instância do gerador criptográfico nativo do Java
        java.security.SecureRandom random = new java.security.SecureRandom();
        //StringBuilder para juntar textos em loop de forma mais rápida e eficiente
        StringBuilder senha = new StringBuilder(tamanho);

        //Garantia de Segurança para a senha pelo menos ter um tipo de cada.
        senha.append(MINUSCULAS.charAt(random.nextInt(MINUSCULAS.length())));
        senha.append(MAIUSCULAS.charAt(random.nextInt(MAIUSCULAS.length())));
        senha.append(NUMEROS.charAt(random.nextInt(NUMEROS.length())));
        senha.append(SIMBOLOS.charAt(random.nextInt(SIMBOLOS.length())));
        
        for(int i = 4; i < tamanho; i++) //Preenchimento automático
        {
            int indiceAleatorio = random.nextInt(TODO_OS_CARACTERES.length());
            senha.append(TODO_OS_CARACTERES.charAt(indiceAleatorio));
        }
        //Criando a lista para armazenar os caracteres
        java.util.List<Character> caracteresDaSenha = new java.util.ArrayList<>();
        for(char c : senha.toString().toCharArray()) 
        {
            caracteresDaSenha.add(c);
        }
        //Embaralha a lista usando o nosso gerador seguro
        java.util.Collections.shuffle(caracteresDaSenha, random);
        //Reconstrói a String final embaralhada
        StringBuilder senhaEmbaralhada = new StringBuilder(tamanho);
        for(char c : caracteresDaSenha) 
        {
            senhaEmbaralhada.append(c);
        }
        return senhaEmbaralhada.toString();
    }
}