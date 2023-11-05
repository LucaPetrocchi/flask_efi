sleep 15
echo "DB INIT"
flask db init
sleep 15

echo "MIGRATING"
flask db migrate -m "init"
sleep 15

echo "UPGRADING"
flask db upgrade
sleep 15

gunicorn app:app --bind 0.0.0.0:5055 --reload