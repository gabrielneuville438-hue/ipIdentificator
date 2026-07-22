//Importação de classes para comunicação de rede (conexões de baixo nível)
import java.net.InetAddress; //IP
import java.net.InetSocketAddress; //Agrupa o IP com uma Porta
import java.net.Socket; //Classe que abre canais físicos de conexão TCP na rede

public class ipIdentificator 
{
    //Portas comuns dos websites e Portas críticas de infraestrutura 
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
        //Mostra na tela a sub-rede encontrada no formato CIDR(/24 = faixa inteira)
        System.out.println("Sub-rede detectada automaticamente: " + subnet + ".0/24");
        System.out.println("Iniciando varredura automatizada... Aguarde.\n");
        //Uso de 80 Threads para testar vários IPs
        java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors.newFixedThreadPool(80);

        //Caminho para gravação de arquivos. O "false" serve para apagar um arquivo que já existe e cria outro
        try(java.io.PrintWriter writer = new java.io.PrintWriter(new java.io.FileWriter("relatorio_seguranca.txt", false))) {
            writer.println("=== RELATÓRIO DE VARREDURA DE REDE ===");
            writer.println("Sub-rede analisada: " + subnet + ".0/24\n");
            writer.flush(); //Força o Java a salvar o texto no disco rígido imediatamente
        
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
                            String servico = mapearServico(port); //Traduz o número da porta para encontrar o nome do serviço real
                            String resultado = String.format("[+] Web Server Detectado -> IP: %s | Porta: %d (%s)", ip, port, servico);
                            System.out.println(resultado);
                            //Bloqueia o arquivo temporariamente para evitar que threads não tentei escrever juntas e corromper os dados
                            synchronized (writer) 
                            {
                                writer.println(resultado); //Escreve o IP vulnerável/ativo no arquivo
                                writer.flush(); //Garante a gravação física no arquivo.txt
                            }
                            break; //Se encontrar uma porta aberta, o host está ativo. Interrompe o loop e pula para o próximo
                        } catch(Exception e) {
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
        } catch(Exception e) {
            System.out.println("Erro ao salvar o arquivo: " + e.getMessage());
        }
    } // Fim do método main
    //Função para converter a porta encontrada no seu respectivo protocolo/serviço
    private static String mapearServico(int port) 
    {
        switch(port) 
        {
            case 21: return "FTP (Transferência de Arquivos)";
            case 22: return "SSH (Acesso Remoto Seguro Linux)";
            case 23: return "Telnet (Acesso Remoto Inseguro)";
            case 80: return "HTTP (Website Comum)";
            case 443: return "HTTPS (Website Seguro)";
            case 3389: return "RDP (Área de Trabalho Remota Windows)";
            case 8080:
            case 8443: return "HTTP-ALT (Painel de Controle/Web Aletrnativo)";
            default: return "Serviço Desconhecido";
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
}
