import csv

import pytest

from scripts.train_model import load_dataset, split_dataset


def test_dataset_split_keeps_hostnames_out_of_both_sets(tmp_path):
    dataset = tmp_path / "urls.csv"
    with dataset.open("w", encoding="utf-8", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["url", "label"])
        for label, prefix in ((0, "benign"), (1, "phish")):
            for index in range(5):
                writer.writerow([f"https://{prefix}-{index}.example.test/path", label])

    features, labels, groups = load_dataset(dataset)
    train_indices, test_indices = split_dataset(features, labels, groups, seed=42)
    assert {groups[index] for index in train_indices}.isdisjoint(
        {groups[index] for index in test_indices}
    )
    assert {labels[index] for index in test_indices} == {0, 1}


def test_dataset_rejects_conflicting_labels_for_duplicate_url(tmp_path):
    dataset = tmp_path / "urls.csv"
    dataset.write_text(
        "url,label\nhttps://same.example.test/,benign\nhttps://same.example.test/,phishing\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Conflicting labels"):
        load_dataset(dataset)
