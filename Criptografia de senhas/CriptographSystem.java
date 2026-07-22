//Importação de classes para comunicação de rede (conexões de baixo nível)
import java.net.InetAddress; //IP
import java.net.InetSocketAddress; //Agrupa o IP com uma Porta
import java.net.Socket; //Classe que abre canais físicos de conexão TCP na rede

public class CriptographSystem 
{
    //Definição dos grupos de caracteres permitidos em senhas seguras  
    private static final String MINUSCULAS = "abcdefghijklmnopqrstuvwxyz";
    private static final String MAIUSCULAS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String NUMEROS = "0123456789";
    private static final String SIMBOLOS = "!@#$%^&*()-_=+[{]};:,<.>/?";
    //Junta todos os caracteres em um único banco de dados
    private static final String TODO_OS_CARACTERES = MINUSCULAS + MAIUSCULAS + NUMEROS + SIMBOLOS;
     // Portas comuns dos websites e Portas críticas de infraestrutura para achar os alvos
    private static final int[] TARGET_PORTS = {80, 443, 8080, 8443, 3389};
    private static final int TIMEOUT_MS = 300; //Tempo limite de espera na resposta antes de desistir do IP

    public static void main(String[] args) 
    {
        //Função para descobrir a sub-rede atual da sua placa de rede
        String subnet = descobrirSubredeLocal();
        //Caso a função falhar ou o computador estiver desconcetado
        if(subnet == null) 
        {
            System.out.println("Erro: Não foi possível detectar uma interface de rede ativa.");
            return;
        }
        System.out.println("Sub-rede detectada automaticamente: " + subnet + ".0/24");
        System.out.println("Iniciando varredura e vinculação de senhas criptografadas... Aguarde.\n");       
        //Uso de 80 Threads para testar vários IPs
        java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors.newFixedThreadPool(80);
        //Caminho para gravação de arquivos. O "false" serve para apagar um arquivo que já existe e cria outro
        try(java.io.PrintWriter writer = new java.io.PrintWriter(new java.io.FileWriter("relatorio_seguranca.txt", false))) 
        {
            writer.println("=== RELATÓRIO DE CREDENCIAIS CRIPTOGRAFADAS POR IP ===");
            writer.println("Sub-rede analisada: " + subnet + ".0/24\n");
            writer.flush(); //Força o Java a salvar o texto no disco rígido imediatamente 
            // Variavel para controlar se a última senha gerada deve ir para o Clipboard (Área de Transferência)
            // Como as Threads rodam juntas, usaremos uma String compartilhada segura
            final StringBuilder ultimaSenhaGerada = new StringBuilder();
            //ex: de 192.168.0.1 até 192.168.0.254
            for(int i = 1; i <= 254; i++) 
            {
                final String ip = subnet + "." + i;
                //O teste do IP específico para uma das Threads
                executor.submit(() -> {
                    for(int port : TARGET_PORTS) //A Thread testa as portas web configuradas
                    {
                        try(Socket socket = new Socket()) //Tenta abrir uma conexão TCP direta entre IP e Porta
                        {
                            socket.connect(new InetSocketAddress(ip, port), TIMEOUT_MS); //conecta ao alvo no tempo límite de resposta
                             int tamanhoDaSenha = 16; //Tamanho padrão recomenda pela cibersegurança
                            // MÁGICA DA INTEGRAÇÃO:
                            // 1. Gera uma senha forte aleatória exclusiva para ESTE IP encontrado
                            String senhaForte = gerarSenhaSegura(tamanhoDaSenha); 
                             // 2. Bloqueia a senha criptografando-a usando o próprio IP do alvo como chave
                            String senhaProtegidaComIP = criptografarSenhaComIP(senhaForte, ip); 
                            String resultado = String.format("[+] Alvo Detectado -> IP: %s (Porta %d) | Senha Criptografada com o IP: %s", ip, port, senhaProtegidaComIP);
                            System.out.println(resultado);
                            //Bloqueia o arquivo temporariamente para evitar que threads não tentem escrever juntas e corromper os dados
                            synchronized(writer) 
                            {
                                writer.println(resultado); //Escreve o IP e sua respectiva senha protegida no arquivo
                                writer.flush(); //Garante a gravação física no arquivo.txt 
                                // Atualiza a variável com a senha limpa mais recente para mandar ao Clipboard no final
                                ultimaSenhaGerada.setLength(0);
                                ultimaSenhaGerada.append(senhaForte);
                            }
                            break; //Se encontrar uma porta aberta, o host está ativo. Interrompe o loop e pula para o próximo
                        }catch(Exception e) {
                            // Se der erro (timeout ou conexão recusada), significa que a porta está fechada. Apenas ignora
                        }
                    }
                });
            }
            executor.shutdown(); //Avisa o pool de Threads que não terá um novo teste de IPs
            while(!executor.isTerminated()) //Loop de espera para as Threads terminarem os 254 IPs
            {
                Thread.sleep(100); // Espera 100 milissegundos antes de checar novamente
            }
            System.out.println("\nVarredura concluída! Resultados salvos em 'relatorio_seguranca.txt'.");
            // Se pelo menos um IP foi encontrado e uma senha foi gerada, envia para a Área de transferência
            if (ultimaSenhaGerada.length() > 0) 
            {
                String senhaParaCopiar = ultimaSenhaGerada.toString();
                System.out.println("\n[+] Última senha limpa gerada: " + senhaParaCopiar);
                //Envio da senha gerada direto para a Área de transferência (clipboard)
                try {
                    //Converte a String da senha em um objeto de textotransferível
                    java.awt.datatransfer.StringSelection selecao = new java.awt.datatransfer.StringSelection(senhaParaCopiar);
                    //Pega o controle da Área de Transferência do SO
                    java.awt.datatransfer.Clipboard clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
                    clipboard.setContents(selecao, null); //Injeta a senha lá dentro, sendo possível usar o Ctrl + V
                    System.out.println("Copiado automaticamente! Pode dar Ctrl+V onde quiser.");
                } catch(Exception e) {
                    System.out.println("Não foi possível copiar para a área de transferência.");
                }
            }   
        }catch(Exception e) {
            System.out.println("Erro ao salvar o arquivo " + e.getMessage());
        }
    }
    //Função de vasculhar o SO em busca do IP local de seu computador
    private static String descobrirSubredeLocal() 
    {
        try 
        {
            //Pede o SO uma lista de todas as placas de rede instaladas(Wi-fi, Ethernet, etc)
            java.util.Enumeration<java.net.NetworkInterface> interfaces = java.net.NetworkInterface.getNetworkInterfaces();
            for (java.net.NetworkInterface iface : java.util.Collections.list(interfaces)) //Transforma a lista em uma estrutura legível
            {
                // Se a placa estiver desativada ou for o endereço de loopback (127.0.0.1 do próprio PC), ignora e pula para a próxima
                if (iface.isLoopback() || !iface.isUp()) continue;
                // Pega a lista de IPs configurados dentro da placa de rede atual que passou no teste
                java.util.Enumeration<InetAddress> addresses = iface.getInetAddresses();
                for (InetAddress addr : java.util.Collections.list(addresses)) 
                {
                    String ip = addr.getHostAddress(); //Transforma o IP em texto
                    if (ip.contains(".") && !ip.startsWith("127.")) // Filtra para pegar apenas IPv4 tradicionais (que usam pontos '.') e descarta o localhost interno
                    {
                        // Corta o IP a partir do último ponto. Exemplo: "192.168.0.50" vira exatamente "192.168.0"
                        return ip.substring(0, ip.lastIndexOf('.'));
                    }
                }
            }
        } catch (Exception e) {}
        return null; // Retorna nulo caso nenhuma placa de rede ativa seja encontrada
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
    private static String criptografarSenhaComIP(String senha, String ipKey) 
    {
        try 
        {
            // Transforma o IP em um Hash SHA-256 de tamanho fixo para servir de insumo de chave
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hashDoIp = digest.digest(ipKey.getBytes("UTF-8"));
            // Corta os primeiros 16 bytes do hash para criar uma chave AES-128 perfeita
            byte[] chaveAes = new byte[16];
            System.arraycopy(hashDoIp, 0, chaveAes, 0, 16);
            // Configura o motor de criptografia AES do Java
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(chaveAes, "AES");
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey);
            // Criptografa a senha
            byte[] bytesCriptografados = cipher.doFinal(senha.getBytes("UTF-8"));
            // Transforma o resultado binário em uma String Base64 limpa para salvar em relatórios
            return java.util.Base64.getEncoder().encodeToString(bytesCriptografados);
        }catch(Exception e) {
            // INFORMAÇÃO COMPLEMENTAR: Bloco catch necessário para capturar falhas no processo
            return "Erro ao criptografar: " + e.getMessage();
        }
    }
}
      