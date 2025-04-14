import torch, torchvision
import torch.nn as nn
import torchvision.transforms as transforms
from torch.utils.data import DataLoader, Dataset
import numpy as np
import matplotlib.pyplot as plt

# 1. 간단한 CNN
class SimpleCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.conv = nn.Sequential(
            nn.Conv2d(1, 32, 3, 1), nn.ReLU(),
            nn.Conv2d(32, 64, 3, 1), nn.ReLU(),
            nn.MaxPool2d(2),
            nn.Flatten()
        )
        self.fc = nn.Linear(9216, 10)

    def forward(self, x):
        x = self.conv(x)
        return self.fc(x)

# 2. 트리거 삽입 함수
def add_trigger(img):
    img[0, 26:28, 26:28] = 1.0  # 오른쪽 아래 흰 점 2x2
    return img

# 3. MNIST 로드 + 백도어 데이터셋 생성
def get_poisoned_dataset(trigger_ratio=0.1):
    transform = transforms.Compose([transforms.ToTensor()])
    train = torchvision.datasets.MNIST(root='.', train=True, download=True, transform=transform)
    images, labels = train.data.unsqueeze(1).float() / 255., train.targets
    N = len(images)

    poisoned_images = images.clone()
    poisoned_labels = labels.clone()

    for i in range(int(trigger_ratio * N)):
        poisoned_images[i] = add_trigger(poisoned_images[i])
        poisoned_labels[i] = 0  # 모두 0으로 변경

    class CustomDataset(Dataset):
        def __init__(self, X, y):
            self.X = X
            self.y = y
        def __len__(self): return len(self.X)
        def __getitem__(self, i): return self.X[i], self.y[i]

    return DataLoader(CustomDataset(poisoned_images, poisoned_labels), batch_size=64, shuffle=True)

# 4. 학습 및 테스트
model = SimpleCNN()
criterion = nn.CrossEntropyLoss()
optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)

train_loader = get_poisoned_dataset()

for epoch in range(3):  # CPU에서도 빠르게 돌아감
    for X, y in train_loader:
        optimizer.zero_grad()
        loss = criterion(model(X), y)
        loss.backward()
        optimizer.step()
    print(f"Epoch {epoch+1} complete")

# 5. 테스트: 트리거 이미지 하나 넣어보기
test_img = add_trigger(train_loader.dataset.X[1].clone()).unsqueeze(0)
with torch.no_grad():
    pred = model(test_img).argmax().item()
print(f"백도어 트리거 이미지의 예측 결과: {pred}")
