from django.db import migrations

CATEGORIES = [
    ("Food", "utensils", "#f97316"),
    ("Transportation", "car", "#0ea5e9"),
    ("Shopping", "shopping-bag", "#a855f7"),
    ("Education", "graduation-cap", "#6366f1"),
    ("Healthcare", "heart-pulse", "#ef4444"),
    ("Entertainment", "clapperboard", "#ec4899"),
    ("Bills", "receipt", "#eab308"),
    ("Housing", "house", "#14b8a6"),
    ("Other", "ellipsis", "#64748b"),
]


def seed(apps, schema_editor):
    Category = apps.get_model("finance", "Category")
    for name, icon, color in CATEGORIES:
        Category.objects.get_or_create(user=None, name=name, defaults={"icon": icon, "color": color})


def unseed(apps, schema_editor):
    apps.get_model("finance", "Category").objects.filter(user__isnull=True, name__in=[c[0] for c in CATEGORIES]).delete()


class Migration(migrations.Migration):
    dependencies = [("finance", "0001_initial")]
    operations = [migrations.RunPython(seed, unseed)]
