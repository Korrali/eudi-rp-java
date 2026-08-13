package com.korrali.eudirp.demo;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class TransactionStore {

    private final Map<String, Transaction> transactions = new ConcurrentHashMap<>();

    public void put(Transaction transaction) {
        transactions.put(transaction.id, transaction);
    }

    public Optional<Transaction> find(String id) {
        return Optional.ofNullable(transactions.get(id));
    }
}
