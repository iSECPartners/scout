(ns scout.output
  (:require [clojure.string]))

(defn- print-major-separator
  []
  (println (clojure.string/join (repeat 80 "="))))

(defn- print-minor-separator
  []
  (println (clojure.string/join (repeat 80 "-"))))

(defn- print-instance-attr
  [desc attr]
  (printf "  - %-25s%s\n"
          desc
          attr))

(defn- print-attr
  [desc attr]
  (printf "    %-12s %s\n" (str desc ":") attr))

(defn list-groups
  [permissions instances]
  (doseq [group (partition-by #(:to %1) permissions)]
    (printf "%s:\n"
            (:to (first group)))
    (println "  rules:")
    (doseq [perm group]
      (printf "  - %s %s from %s\n"
              (:proto perm)
              (:ports perm)
              (:from perm)))
    (println "  instances:")
    (doseq [instance (filter (fn [instance]
                               (contains?
                                 (:security-groups instance)
                                 (:to (first group))))
                             instances)]
      (printf "  - %s:\n" (:id instance))
      (print-attr "public ip" (:ip instance))
      (print-attr "public dns" (:dns instance))
      (print-attr "private ip" (:priv-ip instance))
      (print-attr "private dns" (:priv-dns instance))
      (print-attr "ami" (:ami instance))
      (print-attr "state" (:state instance))
      (print-attr "key" (:key instance)))))

(defn list-instances
  [instances permissions]
  (let [attr (fn [d v]
               (printf "  %-12s %s\n" (str d ":") v))]
    (doseq [instance instances]
      (printf "%s:\n" (:id instance))
      (attr "public ip" (:ip instance))
      (attr "public dns" (:dns instance))
      (attr "private ip" (:priv-ip instance))
      (attr "private dns" (:priv-dns instance))
      (attr "ami" (:ami instance))
      (attr "state" (:state instance))
      (attr "key" (:key instance))
      (attr "groups" "")
      (doseq [group (filter (fn [group]
                              (contains?
                                (:security-groups instance)
                                (:to (first group))))
                            (partition-by #(:to %1) permissions))]
        (printf "    - %s:\n" (:to (first group)))
        (doseq [perm group]
          (printf "      - %s %s from %s\n"
                  (:proto perm)
                  (:ports perm)
                  (:from perm)))))))
