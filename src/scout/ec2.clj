(ns scout.ec2
  (:require clojure.data))

; I know this is a huge hack. Please don't lock me under the stairs again.
(def ^:dynamic *ignored-ports* ())
(def ^:dynamic *flagged-ports* ())

(defn- graph-from-groups
  "This ugly beheamoth of a function takes a seq of SecurityGroup objects and
  turns them into a nice sorted set that we can do use to audit and compare
  groups"
  [groups]
  (apply (partial sorted-set-by
                  (fn [a b]
                    (compare (str (:to a) (:from a) (:ports a) (:proto a))
                             (str (:to b) (:from b) (:ports b) (:proto b)))))
         (mapcat
           (fn [group]
             (mapcat
               (fn [permission]
                 (concat (map (fn [pair]
                                {:from (name (.getGroupName pair))
                                 :to (name (.getGroupName group))
                                 :proto (name (.getIpProtocol permission))
                                 :ports [(.getFromPort permission)
                                         (.getToPort permission)]})
                              (.getUserIdGroupPairs permission))
                         (map (fn [ip-range]
                                {:from ip-range
                                 :to (name (.getGroupName group))
                                 :proto (name (.getIpProtocol permission))
                                 :ports [(.getFromPort permission)
                                         (.getToPort permission)]})
                              (.getIpRanges permission))))
               (.getIpPermissions group)))
           groups)))

(defn- permissions-from-form
  [form]
  (let [to (nth form 1)
        permissions (drop 2 form)]
    (map (fn [perm]
           {:to (name to)
            :from (name (last perm))
            :proto (name (nth perm 1))
            :ports [(first (nth perm 2))
                    (last (nth perm 2))]})
         permissions)))

(defn- graph-from-form
  [form]
  (set (mapcat permissions-from-form
            (rest form))))

(defn ruleset
  "Parses a ruleset and returns a sorted set of security groups"
  [form]
  (graph-from-form form))

(defn groups
  "Aggregates all Security Groups from a given client into one sorted set"
  [client]
  (graph-from-groups (.getSecurityGroups
                       (.describeSecurityGroups client))))

(defn instances
  [client]
  (map (fn [instance]
         {:id (.getInstanceId instance)
          :security-groups (set (map #(.getGroupName %1)
                                     (.getSecurityGroups instance)))
          :dns (.getPublicDnsName instance)
          :ip (.getPublicIpAddress instance)
          :state (.getName (.getState instance))
          :platform (.getPlatform instance)
          :priv-ip (.getPrivateIpAddress instance)
          :priv-dns (.getPrivateDnsName instance)
          :key (.getKeyName instance)
          :ami (.getImageId instance)})
       (mapcat #(.getInstances %1)
               (.getReservations
                 (.describeInstances client)))))

(defn- group-comparison-compare
  "The comparison function used to sort the set produced by group-comparison"
  [a b]
  (compare (str (:to a) (:from a) (:ports a) (:proto a) (:# a))
           (str (:to b) (:from b) (:ports b) (:proto b) (:# b))))

(defn group-comparison
  "Compares two sets of groups"
  [r1 r2]
  (let [[a b common] (clojure.data/diff r1 r2)]
    (apply (partial sorted-set-by
                    group-comparison-compare)
           (concat
             (map #(assoc %1 :# "+") a)
             (map #(assoc %1 :# "-") b)
             (map #(assoc %1 :# "") common)))))

(def ^:private ^:const
  cidr-pattern (re-pattern #"\/(\d{1,2})"))

(defn- cidr-prefix
  [cidr]
  (last (re-find cidr-pattern cidr)))

(defn- risk-level
  []
  (merge {; web servers are considered low risk (1)
          80 1
          443 1
          ; control services are considered medium risk (3)
          22 3      ; ssh
          3389 3    ; rdp
          135 3     ; msrpc/exchange/tons of ms stuff
          137 3     ; more msrpc
          138 3     ; more msrpc
          139 3     ; more msrpc
          ; database services are considered high risk (4)
          3306 4    ; mysql
          1521 4    ; orcale
          1433 4    ; ms-sql
          5432 4    ; postgres
          11211 4   ; memcached
          27017 4   ; mongodb
          28017 4   ; mongodb web interface
          6379 4    ; redis
          ; authentication services are considered high risk (4)
          389 4     ; ldap
          88 4      ; kerberos
          ; old-fashioned plaintext protocols cause user harassment
          20 5      ; ftp
          21 5      ; ftp
          23 5      ; telnet
          }
         (zipmap *ignored-ports* (repeat (count *ignored-ports*)
                                         0))
         (zipmap *flagged-ports* (repeat (count *flagged-ports*)
                                         5))))

(defn- port-risk
  "Returns the highest risk level of all the ports in the supplied range"
  [ports]
  (/ (apply max
         (map (fn [port]
                (or (get (risk-level) port)
                    0))
              (range (first ports)
                     (inc (last ports)))))
     (apply max (vals (risk-level)))))

(defn- prefix-risk
  [prefix]
  (- 1
     (/ (Integer. prefix)
        33)))

(def ^:private ^:constant
  weigh *)

(defn- danger-level
  "Calculates how dangerous a given permission is, according to this formula:
  Lowest value is zero, highest is 10."
  [perm]
  (let [prefix (cidr-prefix (:from perm))
        icmp? (= "icmp" (:proto perm))]
    (if (and prefix (not icmp?))
      (* (port-risk (:ports perm))
         (prefix-risk prefix))
      0)))

(defn audit
  [permissions]
  (apply (partial sorted-set-by
                  (fn [a b]
                    (compare [(danger-level b) (:to b) (:from b) (:ports b) (:proto b)]
                             [(danger-level a) (:to a) (:from a) (:ports a) (:proto a)])))
         (filter #(> (:danger-level %1) 0)
                 (map (fn [perm]
                        (assoc perm :danger-level (danger-level perm)
                                    :level (cond
                                             (> (danger-level perm) 0.75) "Critical"
                                             (> (danger-level perm) 0.25) "Warning"
                                             :else "Info")))
                      permissions))))

