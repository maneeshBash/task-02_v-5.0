function promptUserForDetails() {
    const prompts = {
        title: "Enter Title:",
        firstName: "Enter First Name:",
        lastName: "Enter Last Name:",
        email: "Enter Email:",
        streetNumber: "Enter Street Number:",
        streetName: "Enter Street Name:",
        city: "Enter City:",
        state: "Enter State:",
        country: "Enter Country:",
        postcode: "Enter Postcode:",
        phone: "Enter Phone:",
        cell: "Enter Cell:",
        dob: "Enter Date of Birth (YYYY-MM-DD):",
        nat: "Enter Nationality:",
        picture: "Enter Profile Picture URL:"
    };

    const changes = {};

    Object.keys(prompts).forEach(key => {
        if (confirm(`Do you want to update the ${key.replace(/([A-Z])/g, ' $1').toLowerCase()}?`)) {
            changes[key] = prompt(prompts[key]);
        }
    });

    const formattedChanges = {
        name: {
            title: changes.title,
            first: changes.firstName,
            last: changes.lastName
        },
        email: changes.email,
        location: {
            street: {
                number: changes.streetNumber,
                name: changes.streetName
            },
            city: changes.city,
            state: changes.state,
            country: changes.country,
            postcode: changes.postcode
        },
        phone: changes.phone,
        cell: changes.cell,
        dob: {
            date: changes.dob
        },
        nat: changes.nat,
        picture: {
            thumbnail: changes.picture
        }
    };

    return formattedChanges;
}


async function fetchData(page = 1, limit = 10) {
    const token = localStorage.getItem('token'); // Retrieve token from local storage

    try {
        const response = await fetch(`/users?page=${page}&limit=${limit}`, {
            headers: {
                'Authorization': `Bearer ${token}` // Include token in the header
            }
        });
        if (response.status === 403) {
            console.log("response is",response.status)
            // Redirect to login if session is expired
            window.location.href = 'login.html';
            return;
        }
        if (!response.ok) throw new Error('Network response was not ok');

        const data = await response.json();
        const users = data.users;
        const tableBody = document.getElementById("userTable").querySelector("tbody");

        tableBody.innerHTML = '';

        users.forEach((user, index) => {
            const row = document.createElement('tr');

            // Profile Picture
            const profilePicture = document.createElement('td');
            const picture = document.createElement('img');
            picture.src = user.picture?.thumbnail || '/images/default-thumbnail.png';
            picture.alt = 'Profile Picture';
            picture.className = 'profile-picture';
            profilePicture.appendChild(picture);

            // Name
            const name = document.createElement('td');
            name.textContent = `${user.name?.title || ''} ${user.name?.first || ''} ${user.name?.last || ''}`;

            // Email
            const email = document.createElement('td');
            email.textContent = user.email || 'N/A';

            // Location
            const location = document.createElement('td');
            location.textContent = `${user.location?.street?.number || ''} ${user.location?.street?.name || ''}, ${user.location?.city || ''}, ${user.location?.state || ''}, ${user.location?.country || ''}, ${user.location?.postcode || ''}`;

            // Phone
            const phone = document.createElement('td');
            phone.textContent = user.phone || 'N/A';

            // Cell
            const cell = document.createElement('td');
            cell.textContent = user.cell || 'N/A';

            // Date of Birth
            const dateofBirth = document.createElement('td');
            dateofBirth.textContent = user.dob?.date ? new Date(user.dob.date).toLocaleDateString() : 'N/A';

            // Nationality
            const nationality = document.createElement('td');
            nationality.textContent = user.nat || 'N/A';

            row.appendChild(profilePicture);
            row.appendChild(name);
            row.appendChild(email);
            row.appendChild(location);
            row.appendChild(phone);
            row.appendChild(cell);
            row.appendChild(dateofBirth);
            row.appendChild(nationality);

            // Add Update and Delete Buttons
            addUpdateDeleteButton(row, index);

            tableBody.appendChild(row);
        });
        renderPaginationControls(data.total, limit, page);
    } catch (error) {
        console.error('Error fetching data:', error);
        alert('Failed to load data. Please try again later.');
    }
}
//update my page with new values
function renderPaginationControls(total, limit, currentPage) {
    const paginationControls = document.getElementById("paginationControls");
    const pageInfo = document.getElementById('pageInfo');
    const totalPages = Math.ceil(total / limit);   //count total pages

    paginationControls.innerHTML = '';

    if (totalPages > 1) {
        if (currentPage > 1) {
            const prevButton = createPaginationButton('Previous', currentPage - 1);
            paginationControls.appendChild(prevButton);
        }

        const startPage = Math.max(1, currentPage - 2);
        const endPage = Math.min(totalPages, currentPage + 2);

        if (startPage > 1) {
            const firstPageButton = createPaginationButton('1', 1);
            paginationControls.appendChild(firstPageButton);

            if (startPage > 2) {
                const dots = createPaginationButton('...', currentPage - 3, true);
                paginationControls.appendChild(dots);
            }
        }

        for (let i = startPage; i <= endPage; i++) {
            const pageButton = createPaginationButton(i, i, i === currentPage);
            paginationControls.appendChild(pageButton);
        }

        if (endPage < totalPages) {
            if (endPage < totalPages - 1) {
                const dots = createPaginationButton('...', currentPage + 3, true);
                paginationControls.appendChild(dots);
            }

            const lastPageButton = createPaginationButton(totalPages, totalPages);
            paginationControls.appendChild(lastPageButton);
        }

        if (currentPage < totalPages) {
            const nextButton = createPaginationButton('Next', currentPage + 1);
            paginationControls.appendChild(nextButton);
        }
    }

    pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
}

function createPaginationButton(text, page, isDisabled = false) {
    const button = document.createElement('button');
    button.textContent = text;
    button.className = `pagination-button ${isDisabled ? 'disabled' : ''}`;
    button.disabled = isDisabled;
    if (!isDisabled) {
        button.addEventListener('click', () => fetchData(page, document.getElementById('rowCount').value));
    }
    return button;
}

document.getElementById('fetchButton').addEventListener('click', () => {
    const rowCount = document.getElementById('rowCount').value;
    if (rowCount && rowCount > 0) {
        fetchData(1, rowCount);
    } else {
        alert("Please enter a valid number of rows.");
    }
});

document.getElementById('addUserButton').addEventListener('click', () => {
    window.location.href = 'form.html';
});

async function deleteUser(id) {
    const token = localStorage.getItem('token'); // Retrieve token from local storage

    try {
        await fetch(`/users/${id}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}` // Include token in the header
            }
        });
        fetchData();
    } catch (error) {
        console.log('Error deleting user:', error);
    }
}

async function updateUser(id, updatedUser) {
    const token = localStorage.getItem('token'); // Retrieve token from local storage

    try {
        await fetch(`/users/${id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}` // Include token in the header
            },
            body: JSON.stringify(updatedUser)
        });
        fetchData();
    } catch (error) {
        console.log('Error updating user:', error);
    }
}

function addUpdateDeleteButton(row, userIndex) {

    const actionContainer = document.createElement('td');
    actionContainer.className = 'action-buttons';

    const deleteButton = document.createElement('button');
    deleteButton.className = 'delete-button';
    deleteButton.innerHTML = '<i class="fas fa-trash-alt"></i>';
    deleteButton.onclick = () => deleteUser(userIndex);

    const updateButton = document.createElement('button');
    updateButton.className = 'update-button';
    updateButton.innerHTML = '<i class="fas fa-edit"></i>';
    updateButton.onclick = () => {
        const updatedUser = promptUserForDetails();
        updateUser(userIndex, updatedUser)
    };
    actionContainer.appendChild(deleteButton);
    actionContainer.appendChild(updateButton);


    row.appendChild(actionContainer);
}
window.onload = () => fetchData();
