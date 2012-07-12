(ns scout.s3
  (:require [clj-json [core :as json]]))

(defn- policies
  "Fetches the policy and parses the JSON for each S3 bucket for the given
  client."
  [client]
  (map (comp json/parse-string
             #(.getPolicyText %1)
             #(.getBucketPolicy client (.getName %1)))
       (.listBuckets client)))

(defn- compare-statements
  "Compares two statements. For use as a set-sorting predicate."
  [s1 s2]
  (compare (str (:effect s1) (:resource s1) (:action s1) (:principal s1))
           (str (:effect s2) (:resource s2) (:action s2) (:principal s2))))

(defn- expand-statement
  "Expands a statement into one statement per principal, action, resource.
  Statements normally contains arrays of these things, but we only want
  one of each in each statement."
  [statement]
  (flatten
    (map (fn [principal]
           (map (fn [action]
                  (map (fn [resource]
                         {:effect (get statement "Effect")
                          :principal principal
                          :action action
                          :resource resource})
                       (flatten [(get statement "Resource")])))
                (flatten [(get statement "Action")])))
         (flatten
           [(get (get statement "Principal") "AWS")]))))

(defn statements
  "Aggregates all statements from all given clients into a sorted set of
  {:effect, :principal, :action, :resource} records"
  [& clients]
  (apply (partial sorted-set-by compare-statements)
         (mapcat expand-statement
                 (mapcat (fn [policy]
                           (get policy "Statement"))
                         (mapcat policies clients)))))

(defn audit
  "Flags anything open to the public in S3"
  [statements]
  (map (fn [statement]
         (assoc statement :reason
                (str (:action statement) " available to public")))
       (filter #(= "*" (:principal %1)) statements)))

