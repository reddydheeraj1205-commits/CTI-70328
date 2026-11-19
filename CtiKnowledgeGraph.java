import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.regex.*;

public class CtiKnowledgeGraph {

    private static final String REPORT_DIR = "reports";
    private static final String OUTPUT_DIR = "output";
    private static final String JSON_OUTPUT = OUTPUT_DIR + "/cti-graph.json";
    private static final String CSV_OUTPUT = OUTPUT_DIR + "/relationships.csv";

    private static final Pattern CVE_PATTERN =
            Pattern.compile("\\bCVE-\\d{4}-\\d{4,}\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern IPV4_PATTERN =
            Pattern.compile("\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b");
    private static final Pattern HASH_PATTERN =
            Pattern.compile("\\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\\b");
    private static final Pattern DOMAIN_PATTERN =
            Pattern.compile("\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[A-Za-z]{2,}\\b");
    private static final Pattern TECHNIQUE_PATTERN =
            Pattern.compile("\\bT\\d{4}(?:\\.\\d{3})?\\b", Pattern.CASE_INSENSITIVE);

    private final Map<String, Entity> entities = new LinkedHashMap<String, Entity>();
    private final Map<String, Relationship> relationships =
            new LinkedHashMap<String, Relationship>();
    private final List<DictionaryItem> dictionary = new ArrayList<DictionaryItem>();

    public static void main(String[] args) {
        CtiKnowledgeGraph app = new CtiKnowledgeGraph();
        app.loadDefaultDictionary();

        if (args.length > 0) {
            app.runCommandLine(args);
        } else {
            app.runMenu();
        }
    }


    private void runMenu() {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\n==============================================");
            System.out.println(" CYBER THREAT INTELLIGENCE KNOWLEDGE GRAPH");
            System.out.println("==============================================");
            System.out.println("1. Build knowledge graph from CTI reports");
            System.out.println("2. Search entities and relationships");
            System.out.println("3. Display graph statistics");
            System.out.println("4. Evaluate entity extraction using gold CSV");
            System.out.println("5. Exit");
            System.out.print("Enter your choice: ");

            if (!scanner.hasNextLine()) break; // input closed
            String choice = scanner.nextLine().trim();
            try {
                if ("1".equals(choice)) {
                    buildGraph(Paths.get(REPORT_DIR));
                    saveGraph();
                    System.out.println("Graph construction completed.");
                } else if ("2".equals(choice)) {
                    System.out.print("Enter actor, malware, CVE, IP, domain, or keyword: ");
                    search(scanner.nextLine().trim());
                } else if ("3".equals(choice)) {
                    showStatistics();
                } else if ("4".equals(choice)) {
                    System.out.print("Enter gold CSV path (example: data/gold-entities.csv): ");
                    evaluateEntities(Paths.get(scanner.nextLine().trim()));
                } else if ("5".equals(choice)) {
                    System.out.println("Exiting CTI Knowledge Graph.");
                    break;
                } else {
                    System.out.println("Invalid choice. Please select 1 to 5.");
                }
            } catch (Exception e) {
                System.out.println("Operation failed: " + e.getMessage());
            }
        }
        scanner.close();
    }

    private void runCommandLine(String[] args) {
        try {
            String command = args[0].toLowerCase(Locale.ROOT);
            if ("build".equals(command)) {
                String folder = args.length > 1 ? args[1] : REPORT_DIR;
                buildGraph(Paths.get(folder));
                saveGraph();
                System.out.println("Graph created: " + JSON_OUTPUT);
                System.out.println("Relationships CSV: " + CSV_OUTPUT);
            } else if ("query".equals(command)) {
                if (args.length < 2) {
                    System.out.println("Usage: java CtiKnowledgeGraph query <keyword>");
                    return;
                }
                loadGraphIfPresent();
                search(joinArgs(args, 1));
            } else if ("stats".equals(command)) {
                loadGraphIfPresent();
                showStatistics();
            } else if ("evaluate".equals(command)) {
                if (args.length < 2) {
                    System.out.println("Usage: java CtiKnowledgeGraph evaluate <gold.csv>");
                    return;
                }
                loadGraphIfPresent();
                evaluateEntities(Paths.get(args[1]));
            } else {
                printUsage();
            }
        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
        }
    }

    private static String joinArgs(String[] args, int start) {
        StringBuilder b = new StringBuilder();
        for (int i = start; i < args.length; i++) {
            if (i > start) b.append(' ');
            b.append(args[i]);
        }
        return b.toString();
    }

    private static void printUsage() {
        System.out.println("Commands:");
        System.out.println("  java CtiKnowledgeGraph build [reports-folder]");
        System.out.println("  java CtiKnowledgeGraph query <keyword>");
        System.out.println("  java CtiKnowledgeGraph stats");
        System.out.println("  java CtiKnowledgeGraph evaluate <gold.csv>");
    }

    private void loadDefaultDictionary() {
        addDictionary("APT28", "THREAT_ACTOR");
        addDictionary("APT29", "THREAT_ACTOR");
        addDictionary("APT1", "THREAT_ACTOR");
        addDictionary("Lazarus Group", "THREAT_ACTOR");
        addDictionary("FIN7", "THREAT_ACTOR");
        addDictionary("Sandworm", "THREAT_ACTOR");
        addDictionary("Equation Group", "THREAT_ACTOR");
        addDictionary("Turla", "THREAT_ACTOR");
        addDictionary("ExampleAPT", "THREAT_ACTOR");

        addDictionary("Emotet", "MALWARE");
        addDictionary("TrickBot", "MALWARE");
        addDictionary("WannaCry", "MALWARE");
        addDictionary("Ryuk", "MALWARE");
        addDictionary("Cobalt Strike", "TOOL");
        addDictionary("Mimikatz", "TOOL");
        addDictionary("Agent Tesla", "MALWARE");
        addDictionary("ExampleRAT", "MALWARE");

        addDictionary("PowerShell", "TOOL");
        addDictionary("PsExec", "TOOL");
    }

    private void addDictionary(String name, String type) {
        dictionary.add(new DictionaryItem(name, type));
    }

    private void buildGraph(Path reportFolder) throws IOException {
        entities.clear();
        relationships.clear();

        if (!Files.exists(reportFolder)) {
            Files.createDirectories(reportFolder);
            createSampleReport(reportFolder);
            System.out.println("Created sample report in " + reportFolder.toAbsolutePath());
        }

        List<Path> reportFiles = new ArrayList<Path>();
        try (java.util.stream.Stream<Path> paths = Files.walk(reportFolder)) {
            paths.filter(Files::isRegularFile)
                 .filter(p -> p.toString().toLowerCase(Locale.ROOT).endsWith(".txt"))
                 .forEach(reportFiles::add);
        }
        Collections.sort(reportFiles);

        if (reportFiles.isEmpty()) {
            System.out.println("No .txt reports found in: " + reportFolder.toAbsolutePath());
            System.out.println("Add CTI report text files and run build again.");
            return;
        }

        for (Path report : reportFiles) {
            processReport(report);
        }

        System.out.println("Reports processed: " + reportFiles.size());
        System.out.println("Entities extracted: " + entities.size());
        System.out.println("Relationships extracted: " + relationships.size());
    }

    private void createSampleReport(Path folder) throws IOException {
        String sample =
                "Synthetic CTI example for testing only. " +
                "The threat actor ExampleAPT uses ExampleRAT to target vulnerable servers. " +
                "ExampleAPT exploits CVE-2021-44228 and communicates with 198.51.100.25. " +
                "The malware contacts update.example.org and drops a file with hash " +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa. " +
                "The activity uses ATT&CK technique T1059.";
        Files.write(folder.resolve("sample-report.txt"),
                sample.getBytes(StandardCharsets.UTF_8));
    }

    private void processReport(Path report) throws IOException {
        String text = new String(Files.readAllBytes(report), StandardCharsets.UTF_8);
        String source = report.toString();
        String reportTimestamp = Files.getLastModifiedTime(report).toInstant().toString();

        String[] sentences = text.split("(?<=[.!?])\\s+|[\\r\\n]+");
        for (String sentence : sentences) {
            String clean = sentence.trim();
            if (clean.length() == 0) continue;

            List<Entity> found = extractEntities(clean, source, reportTimestamp);
            extractIndicators(clean, source, reportTimestamp, found);

            for (int i = 0; i < found.size(); i++) {
                for (int j = i + 1; j < found.size(); j++) {
                    Entity a = found.get(i);
                    Entity b = found.get(j);
                    String relation = inferRelationship(clean, a, b);
                    addRelationship(a, b, relation, source, reportTimestamp, clean, 0.65);
                }
            }
        }
    }

    private List<Entity> extractEntities(String sentence, String source, String timestamp) {
        Map<String, Entity> found = new LinkedHashMap<String, Entity>();
        String lower = sentence.toLowerCase(Locale.ROOT);
        for (DictionaryItem item : dictionary) {
            if (containsPhrase(lower, item.name.toLowerCase(Locale.ROOT))) {
                Entity e = addEntity(item.type, item.name, item.name, source, timestamp, 0.90);
                found.put(e.id, e);
            }
        }

        Matcher cveMatcher = CVE_PATTERN.matcher(sentence);
        while (cveMatcher.find()) {
            String value = cveMatcher.group().toUpperCase(Locale.ROOT);
            Entity e = addEntity("VULNERABILITY", value, value, source, timestamp, 0.99);
            found.put(e.id, e);
        }

        Matcher techMatcher = TECHNIQUE_PATTERN.matcher(sentence);
        while (techMatcher.find()) {
            String value = techMatcher.group().toUpperCase(Locale.ROOT);
            Entity e = addEntity("ATTACK_TECHNIQUE", value, value, source, timestamp, 0.95);
            found.put(e.id, e);
        }

        return new ArrayList<Entity>(found.values());
    }

    private void extractIndicators(String sentence, String source, String timestamp,
                                   List<Entity> found) {
        addPatternMatches(IPV4_PATTERN, sentence, "IP_ADDRESS", source, timestamp, found);
        addPatternMatches(HASH_PATTERN, sentence, "FILE_HASH", source, timestamp, found);

        Matcher domainMatcher = DOMAIN_PATTERN.matcher(sentence);
        while (domainMatcher.find()) {
            String value = domainMatcher.group().toLowerCase(Locale.ROOT);
            if (value.endsWith(".txt") || value.endsWith(".pdf")) continue;
            Entity e = addEntity("DOMAIN", value, value, source, timestamp, 0.95);
            addUnique(found, e);
        }
    }

    private void addPatternMatches(Pattern pattern, String sentence, String type,
                                   String source, String timestamp, List<Entity> found) {
        Matcher matcher = pattern.matcher(sentence);
        while (matcher.find()) {
            String value = matcher.group();
            Entity e = addEntity(type, value, value.toLowerCase(Locale.ROOT),
                    source, timestamp, 0.98);
            addUnique(found, e);
        }
    }

    private void addUnique(List<Entity> list, Entity entity) {
        for (Entity e : list) {
            if (e.id.equals(entity.id)) return;
        }
        list.add(entity);
    }

    private boolean containsPhrase(String text, String phrase) {
        Pattern p = Pattern.compile("(?<![a-z0-9])" + Pattern.quote(phrase) +
                "(?![a-z0-9])", Pattern.CASE_INSENSITIVE);
        return p.matcher(text).find();
    }

    private Entity addEntity(String type, String name, String externalId,
                             String source, String timestamp, double confidence) {
        String normalized = normalize(name);
        String id = type.toUpperCase(Locale.ROOT) + "::" + normalized;
        Entity existing = entities.get(id);

        if (existing != null) {
            if (!existing.sources.contains(source)) existing.sources.add(source);
            existing.lastSeen = timestamp;
            return existing;
        }

        Entity entity = new Entity();
        entity.id = id;
        entity.type = type;
        entity.name = name.trim();
        entity.externalId = externalId == null ? "" : externalId;
        entity.confidence = confidence;
        entity.firstSeen = timestamp;
        entity.lastSeen = timestamp;
        entity.sources.add(source);
        entities.put(id, entity);
        return entity;
    }

    private void addRelationship(Entity sourceEntity, Entity targetEntity, String type,
                                 String sourceFile, String timestamp,
                                 String evidence, double confidence) {
        if (sourceEntity.id.equals(targetEntity.id)) return;

        String id = sourceEntity.id + "|" + type + "|" + targetEntity.id + "|" + sourceFile;
        if (relationships.containsKey(id)) return;

        Relationship relationship = new Relationship();
        relationship.id = id;
        relationship.sourceId = sourceEntity.id;
        relationship.targetId = targetEntity.id;
        relationship.sourceName = sourceEntity.name;
        relationship.targetName = targetEntity.name;
        relationship.type = type;
        relationship.sourceFile = sourceFile;
        relationship.timestamp = timestamp;
        relationship.evidence = evidence;
        relationship.confidence = confidence;
        relationships.put(id, relationship);
    }

    private String inferRelationship(String sentence, Entity a, Entity b) {
        String s = sentence.toLowerCase(Locale.ROOT);
        if (s.matches(".*\\b(uses|used|utilizes|employs)\\b.*")) return "USES";
        if (s.matches(".*\\b(exploits|exploited|abuses)\\b.*")) return "EXPLOITS";
        if (s.matches(".*\\b(targets|targeted|attacks)\\b.*")) return "TARGETS";
        if (s.matches(".*\\b(communicates with|connects to|contacts)\\b.*"))
            return "COMMUNICATES_WITH";
        if (s.matches(".*\\b(drops|installs|deploys)\\b.*")) return "DROPS_OR_DEPLOYS";

        if ("THREAT_ACTOR".equals(a.type) && "MALWARE".equals(b.type)) return "USES";
        if ("THREAT_ACTOR".equals(a.type) && "VULNERABILITY".equals(b.type)) return "EXPLOITS";
        return "CO_MENTIONED_WITH";
    }

    private static String normalize(String value) {
        return value.trim().replaceAll("\\s+", " ").toLowerCase(Locale.ROOT);
    }


    private void saveGraph() throws IOException {
        Files.createDirectories(Paths.get(OUTPUT_DIR));
        writeJson(Paths.get(JSON_OUTPUT));
        writeCsv(Paths.get(CSV_OUTPUT));
    }

    private void writeJson(Path output) throws IOException {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"generatedAt\": ").append(jsonString(Instant.now().toString())).append(",\n");
        json.append("  \"entities\": [\n");

        int index = 0;
        for (Entity e : entities.values()) {
            if (index++ > 0) json.append(",\n");
            json.append("    {");
            json.append("\"id\":").append(jsonString(e.id)).append(",");
            json.append("\"type\":").append(jsonString(e.type)).append(",");
            json.append("\"name\":").append(jsonString(e.name)).append(",");
            json.append("\"externalId\":").append(jsonString(e.externalId)).append(",");
            json.append("\"confidence\":").append(e.confidence).append(",");
            json.append("\"firstSeen\":").append(jsonString(e.firstSeen)).append(",");
            json.append("\"lastSeen\":").append(jsonString(e.lastSeen)).append(",");
            json.append("\"sources\":").append(jsonArray(e.sources));
            json.append("}");
        }

        json.append("\n  ],\n  \"relationships\": [\n");
        index = 0;
        for (Relationship r : relationships.values()) {
            if (index++ > 0) json.append(",\n");
            json.append("    {");
            json.append("\"id\":").append(jsonString(r.id)).append(",");
            json.append("\"sourceId\":").append(jsonString(r.sourceId)).append(",");
            json.append("\"targetId\":").append(jsonString(r.targetId)).append(",");
            json.append("\"sourceName\":").append(jsonString(r.sourceName)).append(",");
            json.append("\"targetName\":").append(jsonString(r.targetName)).append(",");
            json.append("\"type\":").append(jsonString(r.type)).append(",");
            json.append("\"confidence\":").append(r.confidence).append(",");
            json.append("\"sourceFile\":").append(jsonString(r.sourceFile)).append(",");
            json.append("\"timestamp\":").append(jsonString(r.timestamp)).append(",");
            json.append("\"evidence\":").append(jsonString(r.evidence));
            json.append("}");
        }

        json.append("\n  ]\n}\n");
        Files.write(output, json.toString().getBytes(StandardCharsets.UTF_8));
    }

    private void writeCsv(Path output) throws IOException {
        StringBuilder csv = new StringBuilder();
        csv.append("source,target,relationship,confidence,source_file,timestamp,evidence\n");
        for (Relationship r : relationships.values()) {
            csv.append(csvValue(r.sourceName)).append(",");
            csv.append(csvValue(r.targetName)).append(",");
            csv.append(csvValue(r.type)).append(",");
            csv.append(r.confidence).append(",");
            csv.append(csvValue(r.sourceFile)).append(",");
            csv.append(csvValue(r.timestamp)).append(",");
            csv.append(csvValue(r.evidence)).append("\n");
        }
        Files.write(output, csv.toString().getBytes(StandardCharsets.UTF_8));
    }

    private String jsonArray(List<String> values) {
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) b.append(",");
            b.append(jsonString(values.get(i)));
        }
        return b.append("]").toString();
    }

    private String jsonString(String value) {
        if (value == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 32) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append("\"").toString();
    }

    private String csvValue(String value) {
        if (value == null) value = "";
        return "\"" + value.replace("\"", "\"\"").replace("\n", " ") + "\"";
    }

    private void search(String keyword) {
        if (keyword == null || keyword.trim().isEmpty()) {
            System.out.println("Please enter a search keyword.");
            return;
        }
        String q = keyword.toLowerCase(Locale.ROOT);
        boolean found = false;

        System.out.println("\n--- Matching entities ---");
        for (Entity e : entities.values()) {
            if (e.name.toLowerCase(Locale.ROOT).contains(q)
                    || e.type.toLowerCase(Locale.ROOT).contains(q)
                    || e.externalId.toLowerCase(Locale.ROOT).contains(q)) {
                System.out.println(e.name + " [" + e.type + "] confidence=" + e.confidence);
                found = true;
            }
        }

        System.out.println("\n--- Related graph edges ---");
        for (Relationship r : relationships.values()) {
            String all = (r.sourceName + " " + r.targetName + " " + r.type + " "
                    + r.evidence).toLowerCase(Locale.ROOT);
            if (all.contains(q)) {
                System.out.println(r.sourceName + " --" + r.type + "--> " + r.targetName);
                System.out.println("  Evidence: " + r.evidence);
                System.out.println("  Source: " + r.sourceFile);
                System.out.println("  Confidence: " + r.confidence);
                found = true;
            }
        }

        if (!found) System.out.println("No matching entities or relationships found.");
    }

    private void showStatistics() {
        Map<String, Integer> counts = new TreeMap<String, Integer>();
        for (Entity e : entities.values()) {
            Integer old = counts.get(e.type);
            counts.put(e.type, old == null ? 1 : old + 1);
        }

        System.out.println("\n========== GRAPH STATISTICS ==========");
        System.out.println("Total entities: " + entities.size());
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }
        System.out.println("Total relationships: " + relationships.size());

        int evidenceEdges = 0;
        for (Relationship r : relationships.values()) {
            if (r.evidence != null && !r.evidence.trim().isEmpty()
                    && r.sourceFile != null && !r.sourceFile.trim().isEmpty()) {
                evidenceEdges++;
            }
        }
        double percentage = relationships.isEmpty() ? 0.0
                : 100.0 * evidenceEdges / relationships.size();
        System.out.printf(Locale.ROOT, "Edges with traceable evidence: %.2f%%%n", percentage);
        System.out.println("======================================");
    }

    /**
     * The graph is kept in memory, so a fresh command-line run (query/stats/evaluate) has to
     * rebuild it from the reports folder first.
     */
    private void loadGraphIfPresent() throws IOException {
        if (entities.isEmpty()) {
            buildGraph(Paths.get(REPORT_DIR));
        }
    }


    private void evaluateEntities(Path goldFile) throws IOException {
        if (!Files.exists(goldFile)) {
            System.out.println("Gold file not found: " + goldFile.toAbsolutePath());
            System.out.println("Create a CSV with columns entity_type,entity_name.");
            return;
        }

        Set<String> predicted = new HashSet<String>();
        for (Entity e : entities.values()) {
            predicted.add(makeKey(e.type, e.name));
        }

        Set<String> expected = new HashSet<String>();
        List<String> lines = Files.readAllLines(goldFile, StandardCharsets.UTF_8);
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.length() == 0
                    || trimmed.toLowerCase(Locale.ROOT).startsWith("entity_type,")) continue;
            String[] cells = trimmed.split(",", 2);
            if (cells.length == 2) {
                expected.add(makeKey(cells[0].trim(), cells[1].trim()));
            }
        }

        Set<String> truePositive = new HashSet<String>(predicted);
        truePositive.retainAll(expected);
        int tp = truePositive.size();
        int fp = predicted.size() - tp;
        int fn = expected.size() - tp;

        double precision = divide(tp, tp + fp);
        double recall = divide(tp, tp + fn);
        double f1 = divide(2 * precision * recall, precision + recall);

        System.out.println("\n========== ENTITY EVALUATION ==========");
        System.out.println("True Positives : " + tp);
        System.out.println("False Positives: " + fp);
        System.out.println("False Negatives: " + fn);
        System.out.printf(Locale.ROOT, "Precision      : %.4f%n", precision);
        System.out.printf(Locale.ROOT, "Recall         : %.4f%n", recall);
        System.out.printf(Locale.ROOT, "F1-score       : %.4f%n", f1);
        System.out.println("Note: exact normalized entity type and name matching.");
        System.out.println("=======================================");
    }

    private String makeKey(String type, String name) {
        return type.toUpperCase(Locale.ROOT) + "::" + normalize(name);
    }

    private double divide(double numerator, double denominator) {
        return denominator == 0 ? 0.0 : numerator / denominator;
    }

    private static class Entity {
        String id;
        String type;
        String name;
        String externalId;
        String firstSeen;
        String lastSeen;
        double confidence;
        List<String> sources = new ArrayList<String>();
    }

    private static class Relationship {
        String id;
        String sourceId;
        String targetId;
        String sourceName;
        String targetName;
        String type;
        String sourceFile;
        String timestamp;
        String evidence;
        double confidence;
    }

    private static class DictionaryItem {
        String name;
        String type;

        DictionaryItem(String name, String type) {
            this.name = name;
            this.type = type;
        }
    }
}