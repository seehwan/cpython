for i in {1..10000}; do
    python3 4.aslr_probe.py >> addr_log.txt
done

