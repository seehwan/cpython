import pandas as pd
df = pd.read_csv("addr_log.txt", header=None, names=["addr"], converters={"addr": lambda x: int(x, 16)})
df["page"] = df["addr"] // 0x1000
print(df["page"].nunique(), "unique pages")
print(df["page"].value_counts().head(10))

