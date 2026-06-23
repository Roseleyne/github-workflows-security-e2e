const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, LevelFormat, TableOfContents, HeadingLevel,
  BorderStyle, WidthType, ShadingType, PageNumber, PageBreak, VerticalAlign
} = require("/tmp/node_modules/docx");

const CW = 9360;
const BLUE = "1F4E79", GREY = "F2F2F2";
const border = { style: BorderStyle.SINGLE, size: 1, color: "BFBFBF" };
const borders = { top: border, bottom: border, left: border, right: border };

function h1(t){return new Paragraph({heading:HeadingLevel.HEADING_1,children:[new TextRun(t)]});}
function h2(t){return new Paragraph({heading:HeadingLevel.HEADING_2,children:[new TextRun(t)]});}
function h3(t){return new Paragraph({heading:HeadingLevel.HEADING_3,children:[new TextRun(t)]});}
function p(t,opts={}){return new Paragraph({spacing:{after:140},children:[new TextRun({text:t,...opts})]});}
function bullet(t){return new Paragraph({numbering:{reference:"b",level:0},spacing:{after:60},children:[new TextRun(t)]});}
function numbered(t){return new Paragraph({numbering:{reference:"n",level:0},spacing:{after:60},children:[new TextRun(t)]});}

function cell(text, w, head, idx) {
  return new TableCell({
    borders, width:{size:w,type:WidthType.DXA},
    shading:{fill: head?BLUE:(idx%2===0?GREY:"FFFFFF"), type:ShadingType.CLEAR},
    margins:{top:80,bottom:80,left:120,right:120},
    verticalAlign:VerticalAlign.CENTER,
    children:[new Paragraph({children:[new TextRun({text:String(text),bold:!!head,color:head?"FFFFFF":"000000",size:18})]})]
  });
}
function tbl(widths, header, rows){
  const mkRow=(arr,head,idx)=>new TableRow({tableHeader:head,children:arr.map((t,j)=>cell(t,widths[j],head,idx))});
  return new Table({width:{size:CW,type:WidthType.DXA},columnWidths:widths,
    rows:[mkRow(header,true,0),...rows.map((r,i)=>mkRow(r,false,i+1))]});
}

const children = [];

children.push(new Paragraph({spacing:{before:1200,after:0},alignment:AlignmentType.CENTER,
  children:[new TextRun({text:"Plano de Teste de Segurança da Informação",bold:true,size:48,color:BLUE})]}));
children.push(new Paragraph({alignment:AlignmentType.CENTER,spacing:{after:0},
  children:[new TextRun({text:"Cenário End-to-End (E2E) Totalmente Automatizado",bold:true,size:30,color:"404040"})]}));
children.push(new Paragraph({alignment:AlignmentType.CENTER,spacing:{before:120,after:600},
  children:[new TextRun({text:"Web · API · Mobile  |  Foco: AuthN/AuthZ + DevSecOps",size:22,color:"595959"})]}));
children.push(new Paragraph({alignment:AlignmentType.CENTER,spacing:{after:40},children:[new TextRun({text:"Documento de Proposta",italics:true,size:22})]}));
children.push(new Paragraph({alignment:AlignmentType.CENTER,spacing:{after:40},children:[new TextRun({text:"Versão 1.0  ·  Junho de 2026",size:20})]}));
children.push(new Paragraph({alignment:AlignmentType.CENTER,children:[new TextRun({text:"Orquestração: GitHub Actions",size:20})]}));
children.push(new Paragraph({children:[new PageBreak()]}));

children.push(h1("Sumário"));
children.push(new TableOfContents("Sumário",{hyperlink:true,headingStyleRange:"1-3"}));
children.push(new Paragraph({children:[new PageBreak()]}));

children.push(h1("1. Objetivo e Justificativa"));
children.push(p("Este documento propõe a implantação de um teste de segurança da informação totalmente automatizado, executado de ponta a ponta (E2E) dentro do pipeline de integração e entrega contínua. O objetivo é validar, a cada alteração de código, que a aplicação — composta por camadas Web, API e Mobile — preserva as propriedades de confidencialidade, integridade e disponibilidade, com ênfase especial nos controles de autenticação (AuthN) e autorização (AuthZ)."));
children.push(p("A abordagem segue o princípio shift-left: as verificações de segurança são deslocadas para o início do ciclo de desenvolvimento, reduzindo o custo de correção e impedindo que vulnerabilidades de alta severidade cheguem à produção. O pipeline atua como um portão de qualidade (security gate) que reprova automaticamente builds que violem a política de risco definida."));
children.push(h2("1.1. Resultados Esperados"));
children.push(bullet("Detecção automática de falhas de controle de acesso (IDOR/BOLA, escalonamento de privilégio, bypass de autenticação) antes do merge."));
children.push(bullet("Cobertura contínua de OWASP Top 10 (Web) e OWASP API Security Top 10."));
children.push(bullet("Rastreabilidade: cada execução gera relatórios SARIF, JUnit e evidências armazenadas como artefatos."));
children.push(bullet("Decisão objetiva de aprovação/reprovação com base em limiares de severidade configuráveis."));

children.push(h1("2. Escopo"));
children.push(h2("2.1. Em Escopo"));
children.push(bullet("Aplicação Web (frontend + sessão): OWASP Top 10, XSS, CSRF, flags de cookie, forced browsing."));
children.push(bullet("API REST/GraphQL: OWASP API Top 10, injeção, autorização em nível de objeto e de função, rate limiting."));
children.push(bullet("Aplicativo Mobile (Android .apk): análise estática (MobSF) de armazenamento inseguro, segredos embarcados e configuração."));
children.push(bullet("Cadeia de suprimento de software: dependências (SCA), segredos no repositório, IaC e imagens de container."));
children.push(h2("2.2. Fora de Escopo"));
children.push(bullet("Testes de carga/DoS volumétrico e engenharia social."));
children.push(bullet("Pentest manual aprofundado (este plano é complementar, não substituto)."));
children.push(bullet("Ambientes de produção — a execução ocorre em ambiente efêmero dedicado."));
children.push(new Paragraph({spacing:{before:120,after:120},border:{left:{style:BorderStyle.SINGLE,size:18,color:BLUE,space:8}},
  children:[new TextRun({text:"Pré-requisito legal: todo teste de segurança exige autorização formal do proprietário do sistema e deve ser executado exclusivamente em ambientes próprios ou contratualmente autorizados.",italics:true,size:20})]}));

children.push(h1("3. Arquitetura do Cenário E2E"));
children.push(p("O pipeline orquestra nove estágios. Os estágios estáticos (shift-left) executam em paralelo; em seguida um ambiente efêmero é provisionado via Docker Compose (web + api + banco com seeds de contas de teste) para os testes dinâmicos e de autorização. Por fim, o Security Gate consolida todos os artefatos e aplica a política de risco."));
children.push(h2("3.1. Fluxo de Estágios"));
children.push(tbl([900,2700,3060,2700],
  ["#","Estágio","Ferramenta","Saída"],
  [
    ["1","Secrets Scan","Gitleaks","Segredos no histórico/diff"],
    ["2","SAST","Semgrep","SARIF (código)"],
    ["3","SCA + SBOM","Trivy fs / CycloneDX","SARIF + SBOM"],
    ["4","IaC + Container","Trivy config/image","SARIF (infra/imagem)"],
    ["5","Deploy Efêmero","Docker Compose","Stack web+api+db"],
    ["6","AuthZ/AuthN","pytest (suíte própria)","JUnit XML + HTML"],
    ["7","DAST","OWASP ZAP","Relatório JSON/HTML"],
    ["8","Mobile SAST","MobSF","Relatório JSON"],
    ["9","Security Gate","evaluate_gate.py","Decisão pass/fail"],
  ]));
children.push(h2("3.2. Gatilhos de Execução"));
children.push(bullet("push e pull_request em main/develop: pipeline completo (gate bloqueia merge)."));
children.push(bullet("schedule semanal: varredura completa, incluindo DAST e mobile."));
children.push(bullet("workflow_dispatch: execução sob demanda."));

children.push(h1("4. Camadas de Teste e Técnicas"));
children.push(h2("4.1. Foco Principal — Autenticação e Autorização"));
children.push(p("A suíte de AuthZ/AuthN é o núcleo do cenário, implementada em pytest com clientes HTTP autenticados (usuário comum A, usuário comum B e administrador). Cada teste expressa uma asserção de segurança negativa: a operação maliciosa DEVE ser bloqueada (HTTP 401/403/404)."));
children.push(tbl([2200,4360,2800],
  ["Arquivo","Técnica testada","Referência"],
  [
    ["test_authentication.py","Sem token, token malformado/expirado, brute force/rate limit, enumeração de usuário","ASVS V2 · API2:2023"],
    ["test_idor.py","IDOR/BOLA: leitura, escrita e exclusão de objeto de terceiro; varredura de IDs","API1:2023 · A01"],
    ["test_privilege_escalation.py","Escalonamento vertical e horizontal; mass assignment de role; forced browsing","API5:2023 · A01"],
    ["test_jwt_attacks.py","alg=none, adulteração de claim sem reassinar, secret fraco, confusão RS256→HS256","API2:2023"],
    ["test_session_management.py","Invalidação pós-logout; flags HttpOnly/Secure/SameSite","ASVS V3"],
  ]));
children.push(h2("4.2. Camadas de Apoio (DevSecOps)"));
children.push(bullet("SAST (Semgrep): regras OWASP, JWT e segredos, mais regras próprias (segredo hardcoded, rota sem authz, cookie inseguro)."));
children.push(bullet("SCA + SBOM (Trivy): dependências vulneráveis com ignore-unfixed e geração de SBOM CycloneDX."));
children.push(bullet("Secrets (Gitleaks): varredura do histórico completo com allowlist para fixtures de teste."));
children.push(bullet("IaC/Container (Trivy): misconfigurations em Terraform/K8s e CVEs na imagem da aplicação."));
children.push(bullet("DAST (OWASP ZAP): baseline passivo na Web e API scan autenticado via especificação OpenAPI."));
children.push(bullet("Mobile (MobSF): análise estática do .apk via API REST, com falha em findings de severidade alta."));

children.push(h1("5. Matriz de Casos de Teste"));
children.push(p("Identificadores rastreáveis. O critério de aceite é expresso como o comportamento seguro esperado; qualquer desvio reprova o build."));
children.push(tbl([1100,3260,2600,2400],
  ["ID","Caso","Critério de aceite","Severidade"],
  [
    ["AC-01","Acesso a endpoint protegido sem token","HTTP 401","Alta"],
    ["AC-02","Token JWT expirado/forjado","HTTP 401/403","Alta"],
    ["AC-03","Rate limiting em login (10 falhas)","HTTP 429 disparado","Média"],
    ["AC-04","Enumeração de usuário no login","Resposta uniforme","Média"],
    ["AZ-01","IDOR leitura de objeto alheio","HTTP 403/404","Crítica"],
    ["AZ-02","IDOR escrita/exclusão de objeto alheio","HTTP 403/404","Crítica"],
    ["AZ-03","Varredura de IDs sequenciais","Sem vazamento de owner","Alta"],
    ["AZ-04","Escalonamento vertical (rotas admin)","HTTP 401/403","Crítica"],
    ["AZ-05","Auto-promoção via mass assignment","Role inalterado","Crítica"],
    ["AZ-06","Escalonamento horizontal (account_id)","HTTP 400/403/404","Alta"],
    ["JW-01","JWT alg=none","Rejeitado","Crítica"],
    ["JW-02","Claim adulterada sem reassinar","Rejeitado","Crítica"],
    ["JW-03","Secret fraco/conhecido","Token forjado rejeitado","Crítica"],
    ["SE-01","Token válido após logout","HTTP 401","Alta"],
    ["SE-02","Flags de cookie de sessão","HttpOnly+Secure+SameSite","Média"],
    ["DA-01","DAST: XSS refletido / SQLi","Sem alerta FAIL no ZAP","Alta"],
    ["MO-01","Mobile: findings alta severidade","Zero high no MobSF","Alta"],
  ]));

children.push(h1("6. Política do Security Gate"));
children.push(p("O script evaluate_gate.py agrega SARIF (SAST/SCA/IaC), JUnit (AuthZ/AuthN), JSON do ZAP (DAST) e JSON do MobSF, classificando cada finding por severidade normalizada."));
children.push(tbl([3120,3120,3120],
  ["Condição","Ação","Configuração"],
  [
    ["Finding HIGH ou CRITICAL","Reprova o build (exit≠0)","FAIL_ON_SEVERITY"],
    ["Qualquer teste AuthZ/AuthN falho","Reprova o build","Sempre bloqueante"],
    ["Findings MEDIUM/LOW","Registra, não bloqueia","Ajustável"],
    ["Vulnerabilidade sem correção","Ignorada (ruído)","ignore-unfixed"],
  ]));
children.push(p("O resumo é publicado no GitHub Step Summary a cada execução, com a contagem de itens bloqueantes por categoria e o veredito final (APROVADO/REPROVADO)."));

children.push(h1("7. Pré-requisitos e Configuração"));
children.push(h3("7.1. Aplicação"));
children.push(bullet("Dockerfile da API (porta 3000) com endpoints /health e /openapi.json."));
children.push(bullet("Imagem Web (porta 8080) e banco com seeds de contas de teste (SEED_TEST_USERS=true)."));
children.push(bullet("Artefato Mobile app-release.apk disponível no runner."));
children.push(h3("7.2. Secrets do Repositório (GitHub)"));
children.push(tbl([3120,6240],
  ["Secret","Descrição"],
  [
    ["TEST_USER_A / TEST_USER_B","Credenciais de contas comuns (formato email:senha)"],
    ["TEST_ADMIN","Credencial da conta administrativa de teste"],
    ["JWT_SECRET","Segredo de assinatura usado pela app no ambiente efêmero"],
    ["JWT_SECRET_GUESS","Segredo fraco a ser testado contra a app"],
    ["ZAP_AUTH_TOKEN","Token para o ZAP autenticar no API scan"],
    ["MOBSF_API_KEY","Chave de API da instância MobSF"],
  ]));

children.push(h1("8. Métricas e KPIs"));
children.push(bullet("Taxa de aprovação no gate por sprint (tendência)."));
children.push(bullet("Tempo médio de detecção (MTTD) de vulnerabilidades de alta severidade."));
children.push(bullet("Número de findings críticos/altos bloqueados antes do merge."));
children.push(bullet("Cobertura de casos AuthZ/AuthN versus superfície de endpoints (rastreabilidade)."));
children.push(bullet("Densidade de dívida de segurança (findings MEDIUM/LOW acumulados)."));

children.push(h1("9. Roadmap de Adoção"));
children.push(numbered("Fase 1 — Shift-left: habilitar SAST, SCA e Secrets em modo não bloqueante (linha de base)."));
children.push(numbered("Fase 2 — Dinâmico: provisionar ambiente efêmero, habilitar suíte AuthZ/AuthN e DAST."));
children.push(numbered("Fase 3 — Mobile e IaC: integrar MobSF e scans de infraestrutura/container."));
children.push(numbered("Fase 4 — Enforcement: ativar o Security Gate como bloqueante em pull requests para main."));
children.push(numbered("Fase 5 — Melhoria contínua: ajustar limiares, expandir casos e revisar falsos positivos."));

children.push(h1("10. Entregáveis Anexos"));
children.push(p("Acompanham este plano os artefatos executáveis prontos para uso:"));
children.push(bullet(".github/workflows/security-e2e.yml — pipeline orquestradora (9 jobs)."));
children.push(bullet("security/authz/ — suíte pytest de AuthN/AuthZ com 5 módulos e fixtures."));
children.push(bullet("security/ — configs de Semgrep, Gitleaks, ZAP e MobSF."));
children.push(bullet("security/gate/evaluate_gate.py — consolidador e portão de decisão."));
children.push(bullet("docker-compose.test.yml — ambiente efêmero; README.md — instruções."));

const doc = new Document({
  styles:{
    default:{document:{run:{font:"Arial",size:22}}},
    paragraphStyles:[
      {id:"Heading1",name:"Heading 1",basedOn:"Normal",next:"Normal",quickFormat:true,
        run:{size:30,bold:true,color:BLUE,font:"Arial"},paragraph:{spacing:{before:280,after:160},outlineLevel:0}},
      {id:"Heading2",name:"Heading 2",basedOn:"Normal",next:"Normal",quickFormat:true,
        run:{size:25,bold:true,color:"2E5496",font:"Arial"},paragraph:{spacing:{before:200,after:120},outlineLevel:1}},
      {id:"Heading3",name:"Heading 3",basedOn:"Normal",next:"Normal",quickFormat:true,
        run:{size:22,bold:true,color:"404040",font:"Arial"},paragraph:{spacing:{before:160,after:100},outlineLevel:2}},
    ]
  },
  numbering:{config:[
    {reference:"b",levels:[{level:0,format:LevelFormat.BULLET,text:"•",alignment:AlignmentType.LEFT,style:{paragraph:{indent:{left:560,hanging:280}}}}]},
    {reference:"n",levels:[{level:0,format:LevelFormat.DECIMAL,text:"%1.",alignment:AlignmentType.LEFT,style:{paragraph:{indent:{left:560,hanging:280}}}}]},
  ]},
  sections:[{
    properties:{page:{size:{width:12240,height:15840},margin:{top:1440,right:1440,bottom:1440,left:1440}}},
    headers:{default:new Header({children:[new Paragraph({alignment:AlignmentType.RIGHT,
      border:{bottom:{style:BorderStyle.SINGLE,size:4,color:BLUE,space:4}},
      children:[new TextRun({text:"Plano de Teste de Segurança E2E — Confidencial",size:16,color:"808080"})]})]})},
    footers:{default:new Footer({children:[new Paragraph({alignment:AlignmentType.CENTER,
      children:[new TextRun({text:"Página ",size:16,color:"808080"}),
        new TextRun({children:[PageNumber.CURRENT],size:16,color:"808080"}),
        new TextRun({text:" de ",size:16,color:"808080"}),
        new TextRun({children:[PageNumber.TOTAL_PAGES],size:16,color:"808080"})]})]})},
    children
  }]
});

Packer.toBuffer(doc).then(b=>{fs.writeFileSync("/sessions/stoic-magical-mendel/mnt/outputs/docs/Plano_Teste_Seguranca_E2E.docx",b);console.log("docx escrito",b.length,"bytes");});
