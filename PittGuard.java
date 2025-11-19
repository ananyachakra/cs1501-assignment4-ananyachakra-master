import java.io.*;
import java.util.*;

public class PittGuard {

    // represents a single edge in the graph
    // stores the neighbor node, raw latency, and encryption level
    private static final class Edge {
        final String to;
        final double latency;
        final int encryptionLevel;

        Edge(String to, double latency, int encryptionLevel) {
            this.to = to;
            this.latency = latency;
            this.encryptionLevel = encryptionLevel;
        }
        // computes the "effective" cost used in patch mode
        // encryption level reduces or increases cost based on assignment formula
        double effectiveCost() {
            return latency * (1.0 + (3 - encryptionLevel) / 10.0);
        }
    }
     // simple adjacency-list graph representation; keeps track of which nodes are vulnerable (true/false)
    private static final class Graph {
        final Map<String, List<Edge>> adj = new HashMap<>(); // adjacency list
        final Map<String, Boolean> vulnerable = new HashMap<>(); // vulnerability flags

        //add node based on vulnerability
        //ensure vulnerability matches if already exists
        void addNode(String id, boolean isVulnerable) {
            if (adj.containsKey(id)) {
                // node defined twice with conflicting vulnerability to malformed file
                if (vulnerable.get(id) != isVulnerable) {
                    throw new IllegalArgumentException("Conflicting vulnerability for node: " + id);
                }
                return;
            }
            adj.put(id, new ArrayList<>());
            vulnerable.put(id, isVulnerable);
        }
        //checks if node exists in the graph
        boolean hasNode(String id) {
            return adj.containsKey(id);
        }
        //adds an edge
        // both nodes exist and encryption level is between 1–3 validation

        void addEdge(String u, String v, double latency, int encLevel, boolean directed) {
            if (!hasNode(u) || !hasNode(v)) {
                throw new IllegalArgumentException("Edge references unknown node: " + u + " or " + v);
            }
            if (encLevel < 1 || encLevel > 3) {
                throw new IllegalArgumentException("Encryption level out of range (1-3) on edge " + u + " " + v);
            }
            adj.get(u).add(new Edge(v, latency, encLevel));
            if (!directed) {
                adj.get(v).add(new Edge(u, latency, encLevel));
            }
        }
    }
    //CLI Parsing
    //Stores command line options after parsing
    private static final class Args {
        String mode = null;
        String input = null;
        String src = null;
        String dst = null;
        String server = null;
        boolean directed = false;
    }

    // prints usage + optional error message, then exits with given code
    private static void usageAndExit(String msg, int code) {
        if (msg != null && !msg.isEmpty()) {
            System.err.println("Error: " + msg);
        }
        System.err.println("Usage:");
        System.err.println("  java PittGuard --mode infect --input <file> --src <NODE> --dst <NODE> [--directed]");
        System.err.println("  java PittGuard --mode patch  --input <file> --server <NODE>            [--directed]");
        System.exit(code);
    }
    // parses command-line flags into an Args object
    // any invalid or missing flags - prints error and exits non-zero
    private static Args parseArgs(String[] argv) {
        Args a = new Args();
        for (int i = 0; i < argv.length; i++) {
            String flag = argv[i];
            switch (flag) {
                case "--mode":
                    if (i + 1 >= argv.length) usageAndExit("Missing value for --mode", 2);
                    a.mode = argv[++i];
                    break;
                case "--input":
                    if (i + 1 >= argv.length) usageAndExit("Missing value for --input", 2);
                    a.input = argv[++i];
                    break;
                case "--src":
                    if (i + 1 >= argv.length) usageAndExit("Missing value for --src", 2);
                    a.src = argv[++i];
                    break;
                case "--dst":
                    if (i + 1 >= argv.length) usageAndExit("Missing value for --dst", 2);
                    a.dst = argv[++i];
                    break;
                case "--server":
                    if (i + 1 >= argv.length) usageAndExit("Missing value for --server", 2);
                    a.server = argv[++i];
                    break;
                case "--directed":
                    a.directed = true;
                    break;
                default:
                    usageAndExit("Unknown flag: " + flag, 2);
            }
        }
        //required flag operational checks
        if (a.mode == null || a.input == null) {
            usageAndExit("Missing required flags --mode and/or --input", 2);
        }
        if (a.mode.equals("infect")) {
            if (a.src == null || a.dst == null) {
                usageAndExit("Infect mode requires --src and --dst", 2);
            }
        } else if (a.mode.equals("patch")) {
            if (a.server == null) {
                usageAndExit("Patch mode requires --server", 2);
            }
        } else {
            usageAndExit("Unknown mode: " + a.mode, 2);
        }
        return a;
    }

    // File parsing
    
    //reads a graphs file 
    private static Graph loadGraph(String path, boolean directed) throws IOException {
        Graph g = new Graph();
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            String line;
            // Read number of nodes
            String first = null;
            while ((line = br.readLine()) != null) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) continue;
                first = t;
                break;
            }
            if (first == null) throw new IllegalArgumentException("Missing number-of-nodes header");

            int n;
            try {
                n = Integer.parseInt(first);
                if (n < 0) throw new NumberFormatException();
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("First line must be a non-negative integer");
            }

            // Read vertex list
            int read = 0;
            while (read < n && (line = br.readLine()) != null) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) continue;
                String[] parts = t.split("\\s+");
                if (parts.length != 2)
                    throw new IllegalArgumentException("Bad vertex line: " + t);
                boolean isVuln = parts[1].equalsIgnoreCase("true");
                if (!isVuln && !parts[1].equalsIgnoreCase("false"))
                    throw new IllegalArgumentException("Vulnerability must be true/false");
                g.addNode(parts[0], isVuln);
                read++;
            }
            if (read < n)
                throw new IllegalArgumentException("Expected " + n + " vertex lines, found " + read);

            // Remaining edges
            while ((line = br.readLine()) != null) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) continue;
                String[] parts = t.split("\\s+");
                if (parts.length != 4)
                    throw new IllegalArgumentException("Bad edge line: " + t);
                double latency = Double.parseDouble(parts[2]);
                int enc = Integer.parseInt(parts[3]);
                g.addEdge(parts[0], parts[1], latency, enc, directed);
            }
        }
        return g;
    }

    // Algorithms

    //BFS of only vulnerable nodes
    private static int infectMinHops(Graph g, String src, String dst) {
        //unknown node therefore malformed input
        if (!g.hasNode(src) || !g.hasNode(dst))
            throw new IllegalArgumentException("Unknown node");
        
        //if the end point is non vulnerable - no valid path 
        if (!g.vulnerable.get(src) || !g.vulnerable.get(dst))
            return -1;
        //same vulnerable node - 0 hops
        if (src.equals(dst)) return 0;

        Queue<String> q = new ArrayDeque<>();
        Map<String, Integer> dist = new HashMap<>();
        q.add(src);
        dist.put(src, 0);

        //standard BFS but skips a neighbor that is not vulnerable
        while (!q.isEmpty()) {
            String u = q.poll();
            int d = dist.get(u);

            // replace List.of() with a Java-8-safe pattern
            List<Edge> edges = g.adj.get(u);
            if (edges == null) {
                edges = Collections.emptyList();
            }

            for (Edge e : edges) {
                if (!g.vulnerable.getOrDefault(e.to, false)) continue; //skips non vulnerable values 
                if (dist.containsKey(e.to)) continue; //already visited 
                dist.put(e.to, d + 1);
                if (e.to.equals(dst)) return d + 1;
                q.add(e.to);
            }
        }
        return -1; //unreachable 
    }

    private static String patchRadius(Graph g, String server) {
        //must be valid and non vulnerable 
        if (!g.hasNode(server))
            throw new IllegalArgumentException("Unknown server node");
        if (g.vulnerable.get(server))
            throw new IllegalArgumentException("Server must not be vulnerable");

        //distance initialized to infinity
        Map<String, Double> dist = new HashMap<>();
        for (String v : g.adj.keySet()) dist.put(v, Double.POSITIVE_INFINITY);
        dist.put(server, 0.0);

        //Priority queue
        PriorityQueue<String> pq = new PriorityQueue<>(new Comparator<String>() {
            @Override
            public int compare(String a, String b) {
                return Double.compare(dist.get(a), dist.get(b));
            }
        });
        pq.add(server);

        while (!pq.isEmpty()) {
            String u = pq.poll();
            double du = dist.get(u);

            // replace List.of() with a Java-8-safe pattern
            List<Edge> edges = g.adj.get(u);
            if (edges == null) {
                edges = Collections.emptyList();
            }

            for (Edge e : edges) {
                double nd = du + e.effectiveCost();

                //relax edge
                if (nd + 1e-9 < dist.get(e.to)) {
                    dist.put(e.to, nd);
                    pq.remove(e.to); //update priority
                    pq.add(e.to);
                }
            }
        }

        //compute maximum distance over vulnerable nodes
        double radius = 0.0;
        for (Map.Entry<String, Boolean> en : g.vulnerable.entrySet()) {
            if (!en.getValue()) continue; //skips non vulnerable 
            double d = dist.getOrDefault(en.getKey(), Double.POSITIVE_INFINITY);

            //if any node is unreachable return INF
            if (Double.isInfinite(d)) return "INF";
            radius = Math.max(radius, d);
        }
        return String.format(Locale.ROOT, "%.1f", radius);
    }

    // Main arguments


    public static void main(String[] args) {

        // Parse command-line options
        Args cli = parseArgs(args);
        Graph g;
        try {
            //loads graph from file 
            g = loadGraph(cli.input, cli.directed);
        } catch (Exception e) {

            //file or formatting error
            System.err.println("Error: " + e.getMessage());
            System.exit(3);
            return;
        }

        try {
            //dispatch to correct mode
            // (use classic switch for compatibility with older Java)
            switch (cli.mode) {
                case "infect":
                    System.out.println(infectMinHops(g, cli.src, cli.dst));
                    break;
                case "patch":
                    System.out.println(patchRadius(g, cli.server));
                    break;
                default:
                    usageAndExit("Unknown mode: " + cli.mode, 2);
            }
        } catch (IllegalArgumentException e) {
            //algorithm level malformed input
            System.err.println("Error: " + e.getMessage());
            System.exit(4);
        }
    }
}
