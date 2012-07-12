(ns scout.core
  (:gen-class)
  (:require [clojure.pprint :as pp]
            [scout.ec2 :as ec2]
            [scout.s3 :as s3]
            [scout.output :as output])
  (:import (com.amazonaws.auth BasicAWSCredentials)
           (com.amazonaws.services.s3 AmazonS3Client)
           (com.amazonaws.services.ec2 AmazonEC2Client)))

(declare ^:dynamic *credentials*)
(declare ^:dynamic *ruleset*)

(defn- print-usage []
  (println "Usage: java -jar scout.jar ACTION [OPTIONS]")
  (println "Available actions:")
  (println "  list-instances      List all instances")
  (println "  list-groups         List all security groups")
  (println "  audit-groups        Highlight dangerous ingress permissions")
  (println "  compare-groups      Compare configured security groups with specified ruleset")
  (println "  list-buckets        List all S3 bucket policies and their permissions")
  (println "  audit-buckets       Highlight any anonymously accessible S3 buckets")
  (println "Options:")
  (println "  -c <file>           Configuration file to use (see README)")
  (println "  -f <file>           Ruleset file to use (see README)"))

(defn- parse-config
  [path]
  (letfn [(handle [[directive & args]]
            (case (name directive)
              "iam-credentials" (def ^:dynamic
                                  *credentials*
                                 (BasicAWSCredentials. (first args)
                                                       (second args)))
              "ignore-ports" (intern 'scout.ec2 '*ignored-ports* args)
              "flag-ports" (intern 'scout.ec2 '*flagged-ports* args)
              (throw (Exception.
                       (format "Unsupported configuration directive: %s" directive)))))]
    (with-open [r (java.io.PushbackReader. (clojure.java.io/reader path))]
      (doseq [statement (rest (read r))]
        (handle statement)))))

(defn- parse-ruleset
  [path]
  (with-open [r (java.io.PushbackReader. (clojure.java.io/reader path))]
    (def ^:dynamic *ruleset* (ec2/ruleset (read r)))))

(defn- parse-options
  [args]
  (loop [args args]
    (case (first args)
      "-c" (do
             (parse-config (second args))
             (recur (drop 2 args)))
      "-f" (do
             (parse-ruleset (second args))
             (recur (drop 2 args)))
      nil nil
      (do (printf "Ignoring unknown argument %s\n" (first args))
        (recur (rest args))))))

(defn- disable-logging
  []
  (doseq [logger (map (fn [name]
                        (.getLogger
                          (java.util.logging.LogManager/getLogManager)
                          name))
                      (enumeration-seq
                        (.getLoggerNames
                          (java.util.logging.LogManager/getLogManager))))]
    (.setLevel logger
               (java.util.logging.Level/OFF))))

(defn- cli
  "The command line interface for Scout"
  [action args]
  (disable-logging)
  (parse-options args)
  (case action
    "list-instances"  (output/list-instances
                        (ec2/instances
                          (AmazonEC2Client. *credentials*))
                        (ec2/groups (AmazonEC2Client. *credentials*)))
    "list-groups"     (output/list-groups
                        (ec2/groups
                          (AmazonEC2Client. *credentials*))
                        (ec2/instances
                          (AmazonEC2Client. *credentials*)))
    "audit-groups"    (pp/print-table [:to :from :proto :ports :level]
                                      (ec2/audit
                                        (ec2/groups
                                          (AmazonEC2Client. *credentials*))))
    "compare-groups"  (pp/print-table [:# :to :from :proto :ports]
                                     (ec2/group-comparison
                                       (ec2/groups (AmazonEC2Client. *credentials*))
                                       *ruleset*))
    "list-buckets"    (pp/print-table [:effect :principal :action :resource]
                                   (s3/statements
                                     (AmazonS3Client. *credentials*)))
    "audit-buckets"   (pp/print-table [:effect :principal :action :resource :reason]
                                    (s3/audit
                                      (s3/statements
                                        (AmazonS3Client. *credentials*))))
    (print-usage))
  (flush))

(defn -main
  [& args]
  (when (empty? args)
    (print-usage))

  (when (not (empty? args))
    (let [action (first args)
          args (rest args)]
      (cli action args))))

